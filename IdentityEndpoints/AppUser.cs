using Microsoft.AspNetCore.Identity;

namespace IdentityEndpoints;

public class AppUser : IdentityUser
{
    public virtual ICollection<ApplicationUserClaim> Claims { get; set; }
    public virtual ICollection<ApplicationUserLogin> Logins { get; set; }
    public virtual ICollection<ApplicationUserToken> Tokens { get; set; }
    public virtual ICollection<ApplicationUserRole> UserRoles { get; set; }

    // Additions
    public string FirstName { get; set; } = "";
    public string LastName { get; set; } = "";
}

public class AppRole : IdentityRole
{
    public virtual ICollection<ApplicationUserRole> UserRoles { get; set; }
    public virtual ICollection<ApplicationRoleClaim> RoleClaims { get; set; }
}

public class ApplicationUserRole : IdentityUserRole<string>
{
    public virtual AppUser User { get; set; }
    public virtual AppRole Role { get; set; }
}

public class ApplicationUserClaim : IdentityUserClaim<string>
{
    public virtual AppUser User { get; set; }
}

public class ApplicationUserLogin : IdentityUserLogin<string>
{
    public virtual AppUser User { get; set; }
}

public class ApplicationRoleClaim : IdentityRoleClaim<string>
{
    public virtual AppRole Role { get; set; }
}

public class ApplicationUserToken : IdentityUserToken<string>
{
    public virtual AppUser User { get; set; }
}