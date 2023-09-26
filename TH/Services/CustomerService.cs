using AutoMapper;
using TH.Data;
using TH.Domains;

namespace TH.Services
{
    public class CustomerService : GenericService<Customer>, ICustomerService, IGenericService<Customer>
    {
        public CustomerService(AppDbContext context, ILogger logger, IMapper mapper) : base(context, logger, mapper)
        {
        }
    }
}
