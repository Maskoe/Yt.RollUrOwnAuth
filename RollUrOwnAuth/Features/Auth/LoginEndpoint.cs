using System.Security.Claims;
using FastEndpoints;
using FastEndpoints.Security;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.JsonWebTokens;
using RollUrOwnAuth.Db;

namespace RollUrOwnAuth.Features.Auth;

public class LoginEndpoint : Endpoint<LoginRequest, LoginResponse>
{
    private readonly Context context;

    public LoginEndpoint(Context context)
    {
        this.context = context;
    }

    public override void Configure()
    {
        Post("auth/login");
        AllowAnonymous();
    }

    public override async Task<LoginResponse> ExecuteAsync(LoginRequest req, CancellationToken ct)
    {
        var user = await context.Users.FirstOrDefaultAsync(x => x.Email.ToUpper() == req.Email.ToUpper());

        if (user is null || AuthUtils.VerifyHashedPassword(user.PasswordHash, req.Password) == PasswordVerificationResult.Failed)
            ThrowError("Unauthorized", StatusCodes.Status401Unauthorized);

        var jwt = JWTBearer.CreateToken("MySuperSecretJwtSecretDontTellAnyone",
            expireAt: DateTime.UtcNow.AddDays(7),
            roles: new[] { user.Role },
            claims: new List<Claim>
            {
                new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new(JwtRegisteredClaimNames.Email, user.Email),
            });

        return new LoginResponse { AccessToken = jwt };
    }
}

public sealed class LoginRequest
{
    public required string Email { get; init; }
    public required string Password { get; init; }
}

public class LoginResponse
{
    public required string AccessToken { get; set; }
}