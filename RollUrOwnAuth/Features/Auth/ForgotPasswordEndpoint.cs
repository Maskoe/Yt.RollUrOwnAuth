using FastEndpoints;
using Microsoft.EntityFrameworkCore;
using RollUrOwnAuth.Db;

namespace RollUrOwnAuth.Features.Auth;

public class ForgotPasswordEndpoint : Endpoint<ForgotPasswordRequest>
{
    private readonly Context context;

    public ForgotPasswordEndpoint(Context context)
    {
        this.context = context;
    }

    public override void Configure()
    {
        AllowAnonymous();
        Post("auth/forgot-password");
    }

    public override async Task HandleAsync(ForgotPasswordRequest req, CancellationToken ct)
    {
        var user = await context.Users.FirstOrDefaultAsync(x => x.Email.ToUpper() == req.Email.ToUpper());

        user.ResetToken = AuthUtils.GenerateSecureToken();
        await context.SaveChangesAsync();

        // Send an email with the ResetToken to the user that directs the user to something like
        // myFrontend.com/reset-password?code={IdentityHelper.Base64Encode(user.ResetToken.Code)}
        // then call the ResetPasswordEndpoint from there
    }
}

public class ForgotPasswordRequest
{
    public required string Email { get; init; }
}