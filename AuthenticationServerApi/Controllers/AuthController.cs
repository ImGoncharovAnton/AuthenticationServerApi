using System.Security.Claims;
using AuthenticationServerApi.Models;
using AuthenticationServerApi.Models.Requests;
using AuthenticationServerApi.Models.Responses;
using AuthenticationServerApi.Services.Authenticators;
using AuthenticationServerApi.Services.PasswordHashers;
using AuthenticationServerApi.Services.RefreshTokenRepositories;
using AuthenticationServerApi.Services.TokenGenerators;
using AuthenticationServerApi.Services.TokenValidators;
using AuthenticationServerApi.Services.UserRepositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationServerApi.Controllers
{
    public class AuthController : Controller
    {
        private readonly IUserRepository _userRepository;
        private readonly IPasswordHasher _passwordHasher;
        private readonly Authenticator _authenticator;
        private readonly RefreshTokenValidator _refreshTokenValidator;
        private readonly IRefreshTokenRepository _refreshTokenRepository;

        public AuthController(IUserRepository userRepository, IPasswordHasher passwordHasher, RefreshTokenValidator refreshTokenValidator, IRefreshTokenRepository refreshTokenRepository, Authenticator authenticator)
        {
            _userRepository = userRepository;
            _passwordHasher = passwordHasher;
            _refreshTokenValidator = refreshTokenValidator;
            _refreshTokenRepository = refreshTokenRepository;
            _authenticator = authenticator;
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

            AuthenticatedUserResponse response = await _authenticator.Authenticate(user);
            return Ok(response);
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] RefreshRequest refreshRequest)
        {
            if (!ModelState.IsValid)
                return BadRequestModelState();

            bool isValidRefreshToken = _refreshTokenValidator.Validate(refreshRequest.RefreshToken);
            if (!isValidRefreshToken)
                return BadRequest(new ErrorResponse("Invalid refresh token"));

            RefreshToken refreshTokenDTO = await _refreshTokenRepository.GetByToken(refreshRequest.RefreshToken);
            if (refreshTokenDTO == null)
            {
                return NotFound(new ErrorResponse("Invalid refresh token"));
            }

            await _refreshTokenRepository.Delete(refreshTokenDTO.Id);

            User user = await _userRepository.GetById(refreshTokenDTO.UserId);
            if(user == null)
                return NotFound(new ErrorResponse("User not found"));


            AuthenticatedUserResponse response = await _authenticator.Authenticate(user);
            return Ok(response);
        }

        [Authorize]
        [HttpDelete("logout")]
        public async Task<IActionResult> Logout()
        {
            string rawUserId = HttpContext.User.FindFirstValue("id");

            if (!Guid.TryParse(rawUserId, out Guid userId))
                return Unauthorized();

            await _refreshTokenRepository.DeleteAll(userId);

            return NoContent();
        }

        private IActionResult BadRequestModelState()
        {
            IEnumerable<string> errorMessages =
                ModelState.Values.SelectMany(v => v.Errors.Select(e => e.ErrorMessage));
            
            return BadRequest(new ErrorResponse(errorMessages));
        }
    }
}
