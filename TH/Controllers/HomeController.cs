using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using TH.Models;
using TH.Services;

namespace TH.Controllers
{
    [Authorize(Roles = 
        THDefaults.Doctor + "," + 
        THDefaults.Patient + "," + 
        THDefaults.DoctorUnverified + "," +
        THDefaults.PatientUnverified + "," + 
        THDefaults.Guest)]
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly IWorkContext _workContext;

        public HomeController(ILogger<HomeController> logger, 
            IWorkContext workContext)
        {
            _logger = logger;
            _workContext = workContext;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}