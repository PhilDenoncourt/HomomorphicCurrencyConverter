using Grpc.Net.Client;
using HomomorphicCurrencyConverter.Protos;
using Microsoft.Research.SEAL;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

namespace HomomorphicCurrencyConverterClient
{
    class Program
    {
        static async Task Main(string[] args)
        {
            //Get the secret amount
            Console.WriteLine("Enter the amount of USD to securely convert to CAD");
            var input = Console.ReadLine();

            double usdAmount = Convert.ToDouble(input);

            
            //Get encryption params from the server so we're all speaking correctly to each other
            var encryptionParms = await GetEncryptionParameters();
            using var encryptionParamsStream = new MemoryStream(encryptionParms);
            
            using EncryptionParameters parms = new EncryptionParameters();
            parms.Load(encryptionParamsStream);


            //Setup my secret and public keys using helper methods.  Also create and store the relinearization keys
            using SEALContext context = new SEALContext(parms);

            using KeyGenerator keygen = new KeyGenerator(context);
            using SecretKey sk = keygen.SecretKey;
            keygen.CreatePublicKey(out PublicKey pk);

            using Serializable<RelinKeys> rlk = keygen.CreateRelinKeys();
            using var dataStream = new MemoryStream();

            _ = rlk.Save(dataStream);

            
            //Create the encoder and store the soon to be secured input
            CKKSEncoder encoder = new CKKSEncoder(context);
            using Plaintext plainInput = new Plaintext();
            double scale = Math.Pow(2.0, 20);
            encoder.Encode(usdAmount, scale, plainInput);

            
            //Encrypt the plaintext
            using Encryptor encryptor = new Encryptor(context, pk);
            _ = encryptor.Encrypt(plainInput).Save(dataStream);

            
            //Call the service
            dataStream.Seek(0, SeekOrigin.Begin);
            var cadEncryptedResult = await CallService(dataStream.ToArray());
            using var cadEncryptedStream = new MemoryStream(cadEncryptedResult);


            //Decrypt the results
            using Decryptor decryptor = new Decryptor(context, sk);
            
            using Ciphertext encryptedResult = new Ciphertext();
            encryptedResult.Load(context, cadEncryptedStream);

            using Plaintext plainResult = new Plaintext();
            decryptor.Decrypt(encryptedResult, plainResult);

            var result = new List<double>();
            encoder.Decode(plainResult, result);


            //Display results
            var cad = result[0].ToString("C");
            Console.WriteLine($"${input} USD = {cad} CAD");
            Console.ReadKey();
        }

        private async static Task<byte[]> GetEncryptionParameters()
        {
            using var channel = GrpcChannel.ForAddress("https://localhost:5001");
            var client = new ForeignCurrencyConvertorService.ForeignCurrencyConvertorServiceClient(channel);
            var req = new EncryptionParametersRequest();
            var clientResult = await client.GetEncryptionParametersAsync(req);

            return clientResult.ParmStream.ToByteArray();
        }

        private async static Task<byte[]> CallService(byte[] dataStream)
        {
            using var channel = GrpcChannel.ForAddress("https://localhost:5001");
            var client = new ForeignCurrencyConvertorService.ForeignCurrencyConvertorServiceClient(channel);
            var req = new ConvertRequest();
            req.DataStream = Google.Protobuf.ByteString.CopyFrom(dataStream);
            var response = await client.ConvertUsdToCadAsync(req);
            return response.DataStream.ToByteArray();
        }
    }
}
