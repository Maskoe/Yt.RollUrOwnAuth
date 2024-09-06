using FastEndpoints;
using FastEndpoints.Security;
using FastEndpoints.Swagger;
using Microsoft.EntityFrameworkCore;
using RollUrOwnAuth.Db;

var bld = WebApplication.CreateBuilder();
bld.Services.AddFastEndpoints();
bld.Services.SwaggerDocument();

bld.Services.AddDbContextFactory<Context>(options => options.UseNpgsql("User ID=postgres; Password=postgres; Database=Yt.RollUrOwnAuth; Server=localhost; Port=5432; Include Error Detail=true;"));

bld.Services.AddAuthenticationJwtBearer(x => x.SigningKey = "MySuperSecretJwtSecretDontTellAnyone");
bld.Services.AddAuthorization();

var app = bld.Build();
app.UseAuthentication();
app.UseAuthorization();

app.UseFastEndpoints();
app.UseSwaggerGen();

// Automatically migrate database on start up
var sp = app.Services.CreateScope().ServiceProvider;
var dbContext = sp.GetRequiredService<Context>();
await dbContext.Database.MigrateAsync();

app.Run();