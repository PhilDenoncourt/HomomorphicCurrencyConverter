using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using HomomorphicCurrencyConverter.Protos;
using Microsoft.Research.SEAL;
using Grpc.Core;

namespace HomomorphicCurrencyConverter.Services
{
    public class ForeignCurrencyConverterService: ForeignCurrencyConvertorService.ForeignCurrencyConvertorServiceBase
    {
        public override Task<EncryptionParametersResponse> GetEncryptionParameters(EncryptionParametersRequest req, ServerCallContext context)
        {
            var response = new EncryptionParametersResponse()
            {
                ParmStream = Google.Protobuf.ByteString.CopyFrom(GetParamsStream())
            };

            return Task.FromResult(response);
        }

        private byte[] GetParamsStream()
        {
            using MemoryStream parmsStream = new MemoryStream();

            ulong polyModulusDegree = 8192;
            using EncryptionParameters parms = new EncryptionParameters(SchemeType.CKKS);
            parms.PolyModulusDegree = polyModulusDegree;
            parms.CoeffModulus = CoeffModulus.Create(
                polyModulusDegree, new int[] { 50, 20, 50 });

            var sz = parms.Save(parmsStream);
            parmsStream.Seek(0, SeekOrigin.Begin);

            return parmsStream.ToArray();
        }

        public override Task<ConvertResponse> ConvertUsdToCad(ConvertRequest request, ServerCallContext context)
        {
            //Load the parameters, and setup the streams
            using EncryptionParameters parms = new EncryptionParameters();
            using var parmsStream = new MemoryStream(GetParamsStream());
            using var dataStream = new MemoryStream(request.DataStream.ToByteArray());

            parms.Load(parmsStream);

            
            //Setup the environment
            using SEALContext sealContext = new SEALContext(parms);
            using Evaluator evaluator = new Evaluator(sealContext);

            //Load the keys, and encrypted data
            using RelinKeys rlk = new RelinKeys();
            using Ciphertext encryptedInput = new Ciphertext();

            rlk.Load(sealContext, dataStream);
            encryptedInput.Load(sealContext, dataStream);

            
            //Set up the encoder
            using var encoder = new CKKSEncoder(sealContext);

            
            //Setup the conversion rate so that it can be used for homomorphic operations
            using var conversionRate = new Plaintext();
            double usdToCad = 1.33;
            double scale = Math.Pow(2.0, 20);
            encoder.Encode(usdToCad, scale, conversionRate);

            
            //Do the business logic
            using var encryptedResult = new Ciphertext();
            evaluator.MultiplyPlain(encryptedInput, conversionRate, encryptedResult);

            
            //Relinearize and rescale to save space
            evaluator.RelinearizeInplace(encryptedResult, rlk);
            evaluator.RescaleToNextInplace(encryptedResult);

            
            //Save the encrypted results to the stream
            using var resultStream = new MemoryStream();

            _ = encryptedResult.Save(resultStream);

            
            //Send it back to the client.
            return Task.FromResult(new ConvertResponse()
            {
                DataStream = Google.Protobuf.ByteString.CopyFrom(resultStream.ToArray())
            });
        }

    }
}
