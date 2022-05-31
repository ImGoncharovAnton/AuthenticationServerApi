using AuthenticationServerApi.Models;
using AuthenticationServerApi.Services.PasswordHashers;
using AuthenticationServerApi.Services.TokenGenerators;
using AuthenticationServerApi.Services.UserRepositories;

var builder = WebApplication.CreateBuilder(args);


builder.Services.AddControllers();

AuthenticationConfiguration authenticationConfiguration = new AuthenticationConfiguration();
builder.Configuration.Bind("Authentication", authenticationConfiguration);
builder.Services.AddSingleton(authenticationConfiguration);

builder.Services.AddSingleton<AccessTokenGenerator>();
builder.Services.AddSingleton<IPasswordHasher, BcryptPasswordHasher>();
builder.Services.AddSingleton<IUserRepository, InMemoryUserRepository>();


var app = builder.Build();
app.UseRouting();
app.UseHttpsRedirection();

app.MapGet("/", () => "Hello World!");

app.MapControllers();

app.Run();
