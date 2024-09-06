namespace RollUrOwnAuth.Db;

public class AppUser
{
    public Guid Id { get; set; }
    public string? PasswordHash { get; set; }
    public string? ResetToken { get; set; }
    
    public string Email { get; set; } = "";
    public string FirstName { get; set; } = "";
    public string LastName { get; set; } = "";
    public DateOnly? DateOfBirth { get; set; }
    
    public string Role { get; set; } = "worker";
}