using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
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

        private static string ClientKey = "V1Jn8QQDeXp0oNnSgu5MN9eUFSmrvh8s"; // Insert Client Key Here
        private static string ClientSecret = "G9jdPARgqeJpdqinKnMmnIGiddXYG1pm"; // Insert Client Key Here

        private static readonly HttpClient HttpClient = new HttpClient();

        static void Main(string[] args)
        {
            string requestUrl = "https://api.qasb.americanexpress.com/sb/merchant/v1/acquisitions/sellers"; // APIGEE URL here
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

        public static String GenerateMacTokenV2(String requestUrl, String httpMethod, String requestBody, String apiKey, String secretkey)
        {
            String authToken = null;
            String ts = DateTime.Now.Ticks.ToString(); // String.valueOf(System.currentTimeMillis());
            String nonce = Guid.NewGuid().ToString();        //tosUUID.randomUUID().toString();
            var url = new Uri(requestUrl);
            String resourceUri = url.AbsolutePath;           // uri.getPath();
            String query = "";                               // uri.getQuery();
            if (!string.IsNullOrWhiteSpace(query)) resourceUri = resourceUri + "?" + query;   // if (query != null && !query.isEmpty()) resourceUri = resourceUri + "?" + query;

            String host = url.Host.Trim().ToLower();          //uri.getHost().trim().toLowerCase();
            int port = url.Port;                                            // uri.getPort() == -1 ? uri.toURL().getDefaultPort() : uri.getPort();

            var mac = new HMACSHA256(Encoding.UTF8.GetBytes(secretkey));    // SecretKeySpec key = new SecretKeySpec(secretkey.getBytes("UTF-8"), "HmacSHA256");
            mac.Initialize();                                               // Mac mac = Mac.getInstance("HmacSHA256");
                                                                            // mac.init(key);

            byte[] rawBodyHash = mac.ComputeHash(Encoding.UTF8.GetBytes(requestBody));    //byte[] rawBodyHash = mac.doFinal(requestBody.getBytes("UTF-8"));
            string bodyHash = Convert.ToBase64String(rawBodyHash);                        //String bodyHash = new String(Base64.encodeBase64(rawBodyHash));
            String macInput = ts + "\n" + nonce + "\n" + httpMethod + "\n" + resourceUri + "\n" + host + "\n" + port +
                              "\n" + bodyHash + "\n";

            byte[] signBytes = mac.ComputeHash(Encoding.UTF8.GetBytes(macInput));  // byte[] signBytes = mac.doFinal(macInput.getBytes());
            string signature = Convert.ToBase64String(signBytes);      //String signature = new String(Base64.encodeBase64(signBytes));

            String[] parameters = new String[] { "\"" + apiKey + "\"", "\"" + ts + "\"", "\"" + nonce + "\"", "\"" + signature + "\"", "\"" + bodyHash + "\"" };

            String[] bodyInputs = new String[] { httpMethod, requestUrl, UrlEncoder.Default.Encode(requestBody) };    //String[] bodyInputs = new String[] { httpMethod, requestUrl, URLEncoder.encode(requestBody, "UTF-8") };
            String macBody = string.Format("http_method={0}&url={1}&payload={2}", bodyInputs);
            authToken = String.Format("MAC id={0},ts={1},nonce={2},bodyhash={4}, mac={3}", parameters);

            return authToken;
        }

        public static async Task<bool> SendRequestToSmApiAsync(string url, string resourcePath, string host, int port, string httpMethod, string payload, string nonce, string ts)
        {
            // create request message
            var request = new HttpRequestMessage(HttpMethod.Post, url) { Content = new StringContent(payload) };

            // add headers to the request
            request.Headers.Add("x-amex-api-key", ClientKey);
            request.Headers.Add("x-amex-request-id", Guid.NewGuid().ToString());

            string macAuth = GenerateMacHeader(ClientKey, ClientSecret, resourcePath, host, port, httpMethod, payload, nonce, ts);
            // string macAuth = GenerateMacTokenV2(url,httpMethod,payload, ClientKey, ClientSecret);

            request.Headers.Add("Authorization", macAuth);

            if (request.Content.Headers.ContentType != null)
                request.Content.Headers.ContentType.MediaType = "application/json";

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
    }
}
