using AuthApp2.Authentication;
using System.Text.Json;
using System.Text;

var httpClient = new HttpClient();
// Create a post request with the user name and password
var request = new HttpRequestMessage(HttpMethod.Post, "http://localhost:7093/authentication/login");
request.Content = new StringContent(JsonSerializer.Serialize(new LoginModel()
{
    UserName = userName,
    Password = password
}), Encoding.UTF8, "application/json");
var response = await httpClient.SendAsync(request);
var token = string.Empty;
if (response.IsSuccessStatusCode)
{
    var content = await response.Content.ReadAsStringAsync();
    var jwtToken = JsonSerializer.Deserialize<JwtToken>(content);
    Console.WriteLine(jwtToken.token);
    token = jwtToken.token;
}