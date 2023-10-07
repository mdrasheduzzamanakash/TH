using TH.Models;

namespace TH.Factories
{
    public interface IFindDoctorFactory
    {
        Task<FindDoctorModel> PrepareFindDoctorModelAsync();
    }
}
