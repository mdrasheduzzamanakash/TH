using TH.Domains;

namespace TH.Services
{
    public interface ICustomerService : IGenericService<Customer>
    {
        Task<Customer?> FindByEmailAsync(string email);
        Task<List<Customer>> FindVerifiedDoctorsAsync();
    }
}
