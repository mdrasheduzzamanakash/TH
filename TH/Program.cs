using Microsoft.OpenApi.Models;
using TH.Extensions;

var builder = WebApplication.CreateBuilder(args);

// Add services 
builder.Services.ConfigureApplicationServices(builder);

// Build application 
var app = builder.Build();

// Add middlewares 
app.AddMiddlewares();

// Map the routes 
app.MapControllerRoute(
      name: "areas",
      pattern: "{area:exists}/{controller=Home}/{action=Index}/{id?}");

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

// Run application 
app.Run();
