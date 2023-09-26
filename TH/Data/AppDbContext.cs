using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using TH.Domains;

namespace TH.Data
{
    public class AppDbContext : IdentityDbContext<IdentityUser>
    {
        #region Application part 

        public virtual DbSet<Customer> Customers { get; set; }
        public virtual DbSet<RefreshToken> RefreshTokens { get; set; }

        #endregion

        #region Identity part 
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            SeedRole(builder);
        }

        private static void SeedRole(ModelBuilder builder)
        {
            builder.Entity<IdentityRole>().HasData
                (
                    new IdentityRole() { Name = "Admin", ConcurrencyStamp = "1", NormalizedName = "Admin"},
                    new IdentityRole() { Name = "Registered", ConcurrencyStamp = "2", NormalizedName = "Registered" },
                    new IdentityRole() { Name = "Doctor", ConcurrencyStamp = "3", NormalizedName = "Doctor" },
                    new IdentityRole() { Name = "DoctorUnvarified", ConcurrencyStamp = "4", NormalizedName = "DoctorUnvarified" },
                    new IdentityRole() { Name = "Patient", ConcurrencyStamp = "5", NormalizedName = "Patient" },
                    new IdentityRole() { Name = "Guest", ConcurrencyStamp = "6", NormalizedName = "Guest" }
                );
            
        }
        #endregion
    }

}
