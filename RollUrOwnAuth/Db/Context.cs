using Microsoft.EntityFrameworkCore;

namespace RollUrOwnAuth.Db;

public class Context : DbContext
{
    public DbSet<AppUser> Users { get; set; }
    
    public Context(DbContextOptions<Context> options) : base(options)
    {
    }
}