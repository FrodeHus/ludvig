// See https://aka.ms/new-console-template for more information
Console.WriteLine("Hello, World!");

var client = new HttpClient(){
    BaseAddress = new Uri("https://github.com"),
};

client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", "ghp_123abc1234567890abcdefjiklmnopqrstuv");

var result = await client.GetAsync("/frodehus");