using IdentityEndpoints;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddDbContextFactory<Context>(x => x.UseNpgsql("User ID=postgres; Password=postgres; Database=IdentityEndpoints; Server=localhost; Port=5432; Include Error Detail=true;"));

builder.Services.AddIdentityCore<AppUser>()
    .AddRoles<AppRole>()
    .AddEntityFrameworkStores<Context>()
    .AddApiEndpoints();

builder.Services.AddAuthentication().AddCookie(IdentityConstants.ApplicationScheme);
builder.Services.AddAuthorization();

var app = builder.Build();

app.UseSwagger();
app.UseSwaggerUI();

app.UseAuthentication();
app.UseAuthorization();

app.MapIdentityApi<AppUser>();

app.MapPost("/auth/register", async (string email, string password, UserManager<AppUser> userManager, IUserStore<AppUser> userStore) =>
{
    var emailStore = (IUserEmailStore<AppUser>)userStore;

    if (string.IsNullOrEmpty(email) || email == "err")
        throw new Exception(userManager.ErrorDescriber.InvalidEmail(email).Description);

    var user = new AppUser();
    await userStore.SetUserNameAsync(user, email, CancellationToken.None);
    await emailStore.SetEmailAsync(user, email, CancellationToken.None);
    await userManager.AddPasswordAsync(user, password); // does this work with a non persisted user?
    var result = await userManager.CreateAsync(user, password);
    
    if (!result.Succeeded)
    {
        var allErrors = string.Join(Environment.NewLine, result.Errors.Select(x => x.Description));
        throw new Exception(allErrors);
    }
    
    // send email?

    return Results.Ok();
}).WithOpenApi();

app.MapPost("/auth/updateUser", async (string userId, string email, string role, string firstName, string lastName, UserManager<AppUser> userManager, IUserStore<AppUser> userStore) =>
{
    var emailStore = (IUserEmailStore<AppUser>)userStore;

    var user = await userManager.FindByIdAsync(userId);
    // var user = await userManager.Users.FirstOrDefaultAsync(x => x.Email == email);
    user.FirstName = firstName;
    user.LastName = lastName;

    await userStore.SetUserNameAsync(user, email, CancellationToken.None);
    await emailStore.SetEmailAsync(user, email, CancellationToken.None);
    await userStore.UpdateAsync(user, CancellationToken.None);

    // This only works if a user in your system can only ever have one role
    await userManager.RemoveFromRoleAsync(user, "Admin");
    await userManager.RemoveFromRoleAsync(user, "User");
    var res = await userManager.AddToRoleAsync(user, role);

    return Results.Ok();
}).WithOpenApi();

app.Run();