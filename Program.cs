using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace AmexSmApiClientTest
{
    class Program
    {
        private static readonly string SIGNATURE_FORMAT = "{0}\n{1}\n{2}\n{3}\n{4}\n{5}\n{6}\n";

        private static readonly string AUTH_HEADER_FORMAT =
            "MAC id=\"{0}\",ts=\"{1}\",nonce=\"{2}\",bodyhash=\"{3}\",mac=\"{4}\"";

        private static string ClientKey = "n3U6BKvHkTQ70FFFuA9XD5ZgY9bgogM7"; // Insert Client Key Here
        private static string ClientSecret = "yHFfA3yRonNSWTzSMJXl5vbeYeYu3JtK"; // Insert Client Key Here
        
        private const string CertPath = @"c:\\temp\0\cert\cert.pem";

        private static readonly HttpClient HttpClient = CreateHttpClient();

        static void Main(string[] args)
        {
            string requestUrl = "https://apigateway2sma-qa.americanexpress.com/sb/merchant/v1/acquisitions/sellers"; // APIGEE URL here
            Uri url = new Uri(requestUrl);
            string queryParams = ""; // Query Params needs to be specified in GETcall for HMAC.

            string resourcePath = url.AbsolutePath + queryParams;
            string host = url.Host;
            int port = url.Port;
            string httpMethod = "POST";
            var payload = File.ReadAllText("payload.json");
            //string payload = JsonSerializer.Serialize(ps); // Payload needs tobe set for POST

            string nonce = Guid.NewGuid().ToString();
            string ts = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString();
            string macAuth = GenerateMacHeader(ClientKey, ClientSecret, resourcePath, host, port, httpMethod, payload, nonce, ts);
            //string macAuth = GenerateMacTokenV2(requestUrl, httpMethod, payload, ClientKey, ClientSecret);

            Console.WriteLine("MacAuth token:");
            Console.WriteLine(macAuth);

            var result = SendRequestToSmApiAsync(requestUrl, resourcePath, host, port, httpMethod, payload, nonce, ts).Result;

            Console.ReadKey();
        }

        private static string GenerateMacHeader(string clientKey, string clientSecret, string resourcePath, string host, int port, string httpMethod, string payload, string nonce, string ts)
        {
            //create crypto using client secret
            var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(clientSecret));
            hmac.Initialize();

            //body hash generation
            byte[] rawBodyHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(payload));
            string bodyHash = Convert.ToBase64String(rawBodyHash);
            //create signature
            string signature =
                string.Format(SIGNATURE_FORMAT, ts, nonce, httpMethod, resourcePath, host, port, bodyHash);
            byte[] signatureBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(signature));
            string signatureString = Convert.ToBase64String(signatureBytes);
            return string.Format(AUTH_HEADER_FORMAT, clientKey, ts, nonce, bodyHash, signatureString);

        }

        public static async Task<bool> SendRequestToSmApiAsync(string url, string resourcePath, string host, int port, string httpMethod, string payload, string nonce, string ts)
        {
            // create request message
            var request = new HttpRequestMessage(HttpMethod.Post, url) { Content = new StringContent(payload) };

            // add headers to the request
            request.Headers.Add("x-amex-api-key", ClientKey);
            request.Headers.Add("x-amex-request-id", Guid.NewGuid().ToString());
            request.Headers.Add("origin", "https://rapidpaylegal.com.au");

            string macAuth = GenerateMacHeader(ClientKey, ClientSecret, resourcePath, host, port, httpMethod, payload, nonce, ts);
            // string macAuth = GenerateMacTokenV2(url,httpMethod,payload, ClientKey, ClientSecret);

            request.Headers.Add("Authorization", macAuth);

            if (request.Content.Headers.ContentType != null)
                request.Content.Headers.ContentType.MediaType = "application/json";

            // add cert 
            Console.WriteLine("----------------------------------");
            Console.WriteLine(request.ToString());
            Console.WriteLine("----------------------------------");
            Console.WriteLine();

            // send the request
            using (var response = await HttpClient.SendAsync(request))
            {
                var content = await response.Content.ReadAsStringAsync();
                var status = $"{(int)response.StatusCode}-{response.ReasonPhrase}";
                if (!response.IsSuccessStatusCode)
                {
                    Console.WriteLine();
                    Console.WriteLine();
                    Console.WriteLine($"Request to Amex SM API failed.");
                    Console.WriteLine($"url:{url}");
                    Console.WriteLine($"status:{status}");
                    Console.WriteLine($"content:{content}");
                    return false;
                }
                else
                {
                    Console.WriteLine();
                    Console.WriteLine();
                    Console.WriteLine("Request to Amex SM API was successful!");
                    return true;
                }

            }
        }

        private static HttpClient CreateHttpClient()
        {
            try
            {
                // System.Net.ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

                //var content = File.ReadAllText(CertPath);

                //var contentByte = Convert.FromBase64String(File.ReadAllText(CertPath));

                //File.WriteAllBytes(@"c:\\temp\0\cert\cert3.pem",  contentByte);
                var cert = new X509Certificate2(X509Certificate2.CreateFromCertFile(CertPath));

                var httpHandler = new HttpClientHandler();
                httpHandler.ClientCertificates.Add(cert);

                var httpClient = new HttpClient(httpHandler);

                return httpClient;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }
    }
}
