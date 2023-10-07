using TH.Models;
using TH.Services;

namespace TH.Factories
{
    public class FindDoctorFactory : IFindDoctorFactory
    {
        #region Fields

        private readonly ICustomerService _customerService;

        #endregion


        #region Ctor

        public FindDoctorFactory(ICustomerService customerService)
        {
            _customerService = customerService;
        }

        #endregion


        #region Methods 

        public async Task<FindDoctorModel> PrepareFindDoctorModelAsync()
        {
            var doctors = await _customerService.FindVerifiedDoctorsAsync();
            var indiVidualDoctors = new List<IndividualDoctorModel>();
            foreach(var doctor in doctors)
            {
                indiVidualDoctors.Add(new IndividualDoctorModel()
                {
                    Name = doctor.FirstName + " " + doctor.LastName,
                    profileImageLink = "https://i.imgur.com/LohyFIN.jpg",
                    Id = doctor.Id
                });
            }
            return new FindDoctorModel
            {
                doctors = indiVidualDoctors,
            };
        }

        #endregion
    }
}
