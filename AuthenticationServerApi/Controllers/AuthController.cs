using AuthenticationServerApi.Models;
using AuthenticationServerApi.Models.Requests;
using AuthenticationServerApi.Models.Responses;
using AuthenticationServerApi.Services.PasswordHashers;
using AuthenticationServerApi.Services.TokenGenerators;
using AuthenticationServerApi.Services.UserRepositories;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationServerApi.Controllers
{
    public class AuthController : Controller
    {
        private readonly IUserRepository _userRepository;
        private readonly IPasswordHasher _passwordHasher;
        private readonly AccessTokenGenerator _tokenGenerator;

        public AuthController(IUserRepository userRepository, IPasswordHasher passwordHasher, AccessTokenGenerator tokenGenerator)
        {
            _userRepository = userRepository;
            _passwordHasher = passwordHasher;
            _tokenGenerator = tokenGenerator;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest registerRequest)
        {
            if (!ModelState.IsValid)
                return BadRequestModelState();

                if (registerRequest.Password != registerRequest.ConfirmPassword)
                return BadRequest(new ErrorResponse("Password does not match confirm password"));
            User existingUserByEmail = await _userRepository.GetByEmail(registerRequest.Email);
            if (existingUserByEmail != null)
                return Conflict(new ErrorResponse("Email already exists"));

            User existingUserByUsername = await _userRepository.GetByUsername(registerRequest.Username);
            if (existingUserByUsername != null)
                return Conflict(new ErrorResponse("Username already exists"));

            string passwordHash = _passwordHasher.HashPassword(registerRequest.Password);
            User registrationUser = new User()
            {
                Email = registerRequest.Email,
                Username = registerRequest.Username,
                PasswordHash = passwordHash
            };

            await _userRepository.Create(registrationUser);

            return Ok();

        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest loginRequest)
        {
            if (!ModelState.IsValid)
                return BadRequestModelState();

            User user = await _userRepository.GetByUsername(loginRequest.Username);
            if (user == null)
                return Unauthorized();

            bool isCorrectPassword = _passwordHasher.VerifyPassword(loginRequest.Password, user.PasswordHash);
            if(!isCorrectPassword)
                return Unauthorized();

            string accessToken = _tokenGenerator.GenerateToken(user);

            return Ok(new AuthenticatedUserResponse()
            {
                AccessToken = accessToken
            });
        }


        private IActionResult BadRequestModelState()
        {
            IEnumerable<string> errorMessages =
                ModelState.Values.SelectMany(v => v.Errors.Select(e => e.ErrorMessage));
            
            return BadRequest(new ErrorResponse(errorMessages));
        }
    }
}
