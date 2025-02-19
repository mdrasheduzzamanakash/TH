﻿using AutoMapper;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Configuration;
using System.Text;
using TH.Configurations;
using TH.Data;
using TH.Mapper;
using TH.Middlewares;
using TH.Services;
using TH.Services.Cache;
using TH.Services.ThirdPartyServices;

namespace TH.Extensions
{
    public static class ServiceCollectionExtensions
    {
        
        public static void ConfigureApplicationServices(this IServiceCollection services,
            WebApplicationBuilder builder)
        {
            // For JWT
            builder.Services.Configure<JwtConfig>(builder.Configuration.GetSection("JwtConfig"));
            
            
            // For Entity Framework
            builder.Services.AddDbContext<AppDbContext>(options =>
                options.UseSqlServer(builder.Configuration.GetConnectionString("THDefaultConnection")));

            // For Identity
            builder.Services.AddIdentity<IdentityUser, IdentityRole>()
                .AddEntityFrameworkStores<AppDbContext>()
                .AddDefaultTokenProviders();
            
            // For authentication 
            builder.Services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultSignOutScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            }).AddCookie(options =>
            {
                options.Cookie.Name = THDefaults.AspToken;
                options.LoginPath = THDefaults.LoginUrl;
                options.LogoutPath = THDefaults.LogoutUrl;
                options.AccessDeniedPath = THDefaults.AccessDeniedUrl;
            });


            // For Automapper 
            var config = new MapperConfiguration(cfg =>
            {
                cfg.AddProfile<MappingProfile>();
            });
            IMapper mapper = config.CreateMapper();
            builder.Services.AddSingleton(mapper);

            // Add services to the container.
            builder.Services.AddControllersWithViews();
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();

            // Add accessor to HttpContext
            services.AddHttpContextAccessor();

            // Add services  
            services.AddApplicationServices(builder);

            // Add third party services 
            services.AddThirdPartyServices(builder);
        }

        public static void AddHttpContextAccessor(this IServiceCollection services)
        {
            services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
        }

        public static void AddApplicationServices(this IServiceCollection services, WebApplicationBuilder builder)
        {
            builder.Services.AddScoped<ICustomerService, CustomerService>();
            builder.Services.AddScoped<IRefreshTokenService, RefreshTokenService>();
            builder.Services.AddScoped<ILogService, LogService>();
            builder.Services.AddScoped<IWorkContext, WorkContext>();
            builder.Services.AddSingleton<ICacheService, CacheService>();
        }

        public static void AddThirdPartyServices(this IServiceCollection services, WebApplicationBuilder builder)
        {
            // For SMTP2GO
            builder.Services.Configure<Smtp2GoConfig>(builder.Configuration.GetSection("Smtp2GoConfig"));

            // Add email smtp2go service
            builder.Services.AddScoped<IEmailService, EmailSmtp2GoService>();
        }

        public static void AddMiddlewares(this WebApplication app)
        {
            // Configure the HTTP request pipeline.
            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI(c =>
                {
                    c.SwaggerEndpoint("/swagger/v1/swagger.json", "My API V1");
                });
            }

            app.UseHttpsRedirection();

            app.UseStaticFiles();

            app.UseRouting();

            app.UseCheckForGuestMiddleware(); // Add guest role to new user

            app.UseRefreshTokenMiddleware();

            app.UseAuthentication();

            app.UseAuthorization();

            app.UseWorkContextCreatorMiddleware();

            app.UseCookiePolicy();
        }
    }
}
