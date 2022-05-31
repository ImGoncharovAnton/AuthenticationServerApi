using AuthenticationServerApi.Models;
using AuthenticationServerApi.Services.Authenticators;
using AuthenticationServerApi.Services.PasswordHashers;
using AuthenticationServerApi.Services.RefreshTokenRepositories;
using AuthenticationServerApi.Services.TokenGenerators;
using AuthenticationServerApi.Services.TokenValidators;
using AuthenticationServerApi.Services.UserRepositories;

var builder = WebApplication.CreateBuilder(args);


builder.Services.AddControllers();

AuthenticationConfiguration authenticationConfiguration = new AuthenticationConfiguration();
builder.Configuration.Bind("Authentication", authenticationConfiguration);
builder.Services.AddSingleton(authenticationConfiguration);

builder.Services.AddSingleton<AccessTokenGenerator>();
builder.Services.AddSingleton<RefreshTokenGenerator>();
builder.Services.AddSingleton<RefreshTokenValidator>();
builder.Services.AddSingleton<Authenticator>();
builder.Services.AddSingleton<TokenGenerator>();
builder.Services.AddSingleton<IPasswordHasher, BcryptPasswordHasher>();
builder.Services.AddSingleton<IUserRepository, InMemoryUserRepository>();
builder.Services.AddSingleton<IRefreshTokenRepository, InMemoryRefreshTokenRepository>();


var app = builder.Build();
app.UseRouting();
app.UseHttpsRedirection();

app.MapGet("/", () => "Hello World!");

app.MapControllers();

app.Run();
