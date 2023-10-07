using Microsoft.AspNetCore.Mvc;
using TH.Factories;
using TH.Services;

namespace TH.Controllers
{
    public class DoctorController : Controller
    {
        #region Fields

        private readonly IWorkContext _workContext;
        private readonly ICustomerService _customerService;
        private readonly IFindDoctorFactory _findDoctorFactory;

        #endregion

        #region Ctor 

        public DoctorController(IWorkContext workContext, 
            ICustomerService customerService,
            IFindDoctorFactory findDoctorFactory)
        {
            _workContext = workContext;
            _customerService = customerService;
            _findDoctorFactory = findDoctorFactory;

        }

        #endregion
        public async Task<IActionResult> FindDoctor()
        {
            var model = await _findDoctorFactory.PrepareFindDoctorModelAsync();
            return View(model);
        }


    }
}
