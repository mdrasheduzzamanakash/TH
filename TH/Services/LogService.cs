using AutoMapper;
using TH.Data;
using TH.Domains;

namespace TH.Services
{
    public class LogService : GenericService<Log>, ILogService, IGenericService<Log>
    {
        public LogService(AppDbContext context, IMapper mapper) : base(context, mapper)
        {
        }
    }
}
