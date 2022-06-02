using System.Text;
using AuthenticationServerApi.Models;
using AuthenticationServerApi.Services.Authenticators;
using AuthenticationServerApi.Services.RefreshTokenRepositories;
using AuthenticationServerApi.Services.TokenGenerators;
using AuthenticationServerApi.Services.TokenValidators;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);


builder.Services.AddControllers();

builder.Services.AddIdentityCore<User>(o =>
{
    o.User.RequireUniqueEmail = true;
    o.Password.RequireDigit = true;
    o.Password.RequiredLength = 8;
    o.Password.RequireUppercase = true;
    o.Password.RequiredUniqueChars = 1;
    // o.Lockout.MaxFailedAccessAttempts = 5;
})
    .AddEntityFrameworkStores<AuthenticationDbContext>()
    .AddDefaultTokenProviders();

AuthenticationConfiguration authenticationConfiguration = new AuthenticationConfiguration();
builder.Configuration.Bind("Authentication", authenticationConfiguration);
builder.Services.AddSingleton(authenticationConfiguration);

string connectionString = builder.Configuration.GetConnectionString("AppDbContext");
builder.Services.AddDbContext<AuthenticationDbContext>(o => 
    o.UseSqlServer(connectionString));

builder.Services.AddSingleton<AccessTokenGenerator>();
builder.Services.AddSingleton<RefreshTokenGenerator>();
builder.Services.AddSingleton<RefreshTokenValidator>();
builder.Services.AddScoped<Authenticator>();
builder.Services.AddSingleton<TokenGenerator>();
builder.Services.AddScoped<IRefreshTokenRepository, DatabaseRefreshTokenRepository>();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(o =>
{
    o.TokenValidationParameters = new TokenValidationParameters()
    {
        IssuerSigningKey =
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(authenticationConfiguration.AccessTokenSecret)),
        ValidIssuer = authenticationConfiguration.Issuer,
        ValidAudience = authenticationConfiguration.Audience,
        ValidateIssuerSigningKey = true,
        ValidateIssuer = true,
        ValidateAudience = true,
        ClockSkew = TimeSpan.Zero
    };
});


var app = builder.Build();
app.UseRouting();
app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", () => "Hello World!");

app.MapControllers();

app.Run();
