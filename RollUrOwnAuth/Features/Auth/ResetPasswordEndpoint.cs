using FastEndpoints;
using FluentValidation;
using Microsoft.EntityFrameworkCore;
using RollUrOwnAuth.Db;

namespace RollUrOwnAuth.Features.Auth;

public class ResetPasswordEndpoint : Endpoint<ResetPasswordRequest>
{
    private readonly Context context;

    public ResetPasswordEndpoint(Context context)
    {
        this.context = context;
    }

    public override void Configure()
    {
        Post("auth/reset-password");
        AllowAnonymous();
    }

    public override async Task HandleAsync(ResetPasswordRequest req, CancellationToken ct)
    {
        var user = await context.Users.FirstOrDefaultAsync(x => x.Id == req.UserId);

        if (user is null || user.ResetToken is null || AuthUtils.Base64Decode(req.ResetCode) != user.ResetToken)
            ThrowError("Unauthorized", StatusCodes.Status401Unauthorized);

        user.PasswordHash = AuthUtils.HashPassword(req.Password);
        user.ResetToken = null;
        await context.SaveChangesAsync();
    }
}

public class ResetPasswordRequest : Extensions.IPasswordRequest
{
    public required Guid UserId { get; init; }
    public required string ResetCode { get; init; }
    public required string Password { get; init; }
}

public class ResetPasswordEndpointValidator : Validator<ResetPasswordRequest>
{
    public ResetPasswordEndpointValidator()
    {
        this.ValidatePasswordRules();
    }
}







// If you wanted to extract the password validation to a singular place.
public static class Extensions
{
    public interface IPasswordRequest
    {
        string Password { get; }
    }

    public static void ValidatePasswordRules<T>(this Validator<T> validator) where T : IPasswordRequest
    {
        validator.RuleFor(x => x.Password).MinimumLength(8)
            .WithMessage("Password must be 8 characters or more.");

        validator.RuleFor(x => x.Password).Must(x => x.Any(IsUpper))
            .WithMessage("Password must contain upper case letter.");

        validator.RuleFor(x => x.Password).Must(x => x.Any(IsDigit))
            .WithMessage("Password must contain a digit.");
    }

    private static bool IsDigit(char c) => c >= '0' && c <= '9';
    private static bool IsLower(char c) => c >= 'a' && c <= 'z';
    private static bool IsUpper(char c) => c >= 'A' && c <= 'Z';
    private static bool IsLetterOrDigit(char c) => IsUpper(c) || IsLower(c) || IsDigit(c);
}