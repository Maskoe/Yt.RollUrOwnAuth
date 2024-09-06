using FastEndpoints;
using FluentValidation;
using RollUrOwnAuth.Db;

namespace RollUrOwnAuth.Features.Auth;

public class RegisterEndpoint : Endpoint<RegisterRequest>
{
    private readonly Context context;

    public RegisterEndpoint(Context context)
    {
        this.context = context;
    }

    public override void Configure()
    {
        Post("auth/register");
        AllowAnonymous();
    }

    public override async Task HandleAsync(RegisterRequest req, CancellationToken ct)
    {
        if (context.Users.Any(x => x.Email.ToUpper() == req.Email.ToUpper()))
            ThrowError("Email Already In Use");

        var user = new AppUser()
        {
            FirstName = req.FirstName,
            LastName = req.LastName,
            DateOfBirth = req.DateOfBirth,
            Email = req.Email,
            PasswordHash = AuthUtils.HashPassword(req.Password),
        };

        context.Users.Add(user);
        await context.SaveChangesAsync();
    }
}

public class RegisterEndpointValidator : Validator<RegisterRequest>
{
    public RegisterEndpointValidator()
    {
        RuleFor(x => x.Email).EmailAddress();
        
        RuleFor(x => x.Password).MinimumLength(8)
            .WithMessage("Password must be 8 characters or more.");

        RuleFor(x => x.Password).Must(x => x.Any(IsUpper))
            .WithMessage("Password must contain upper case letter.");

        RuleFor(x => x.Password).Must(x => x.Any(IsDigit))
            .WithMessage("Password must contain a digit.");
    }
    
    private static bool IsDigit(char c) => c >= '0' && c <= '9';
    private static bool IsLower(char c) => c >= 'a' && c <= 'z';
    private static bool IsUpper(char c) => c >= 'A' && c <= 'Z';
    private static bool IsLetterOrDigit(char c) => IsUpper(c) || IsLower(c) || IsDigit(c);
}

public class RegisterRequest
{
    public required string Email { get; init; }
    public required string Password { get; init; }
    public required string FirstName { get; init; }
    public required string LastName { get; init; }
    public DateOnly? DateOfBirth { get; set; }
}