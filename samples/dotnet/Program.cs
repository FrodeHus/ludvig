// See https://aka.ms/new-console-template for more information
Console.WriteLine("Hello, World!");

var client = new HttpClient(){
    BaseAddress = new Uri("https://postman.com"),
};

client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", "PMAK-63bd7db057e290329aff9743-5ada91a8cd8633857e3fb8547be9f7d45c");

var _ = await client.GetAsync("/frodehus");