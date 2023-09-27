using AutoMapper;
using Microsoft.EntityFrameworkCore;
using TH.Data;

namespace TH.Services
{
    public class GenericService<T> : IGenericService<T> where T : class
    {
        #region Fields

        protected readonly AppDbContext _context;
        protected readonly ILogger _logger;
        protected readonly IMapper _mapper;
        protected readonly DbSet<T> _dbSet;

        #endregion

        #region Ctor

        public GenericService(AppDbContext context,  
            ILogger logger, 
            IMapper mapper)
        {
            _context = context;
            _logger = logger;
            _mapper = mapper;
            _dbSet = context.Set<T>();
        }

        #endregion

        #region Methods 

        public async Task<IEnumerable<T>> GetAllAsync()
        {
            return await _dbSet.ToListAsync();
        }

        public async Task<T?> GetByIdAsync(string id)
        {
            return await _dbSet.FindAsync(id);
        }

        public async Task<T?> InsertAsync(T entity)
        {
            try
            {
                await _dbSet.AddAsync(entity);
                await _context.SaveChangesAsync();
                return entity;
            }
            catch (Exception ex)
            {
                await Console.Out.WriteLineAsync(ex.Message);
                return null;
            }
        }

        public async Task<T?> UpdateAsync(T entity, string id)
        {
            try
            {
                var existingEntity = await _dbSet.FindAsync(id);
                if (existingEntity != null)
                {
                    _dbSet.Entry(existingEntity).CurrentValues.SetValues(entity);
                    await _context.SaveChangesAsync();
                    return existingEntity;
                }
                return null;
            }
            catch (Exception ex)
            {
                await Console.Out.WriteLineAsync(ex.Message);
                return null;
            }
        }

        public async Task<bool> DeleteAsync(string id)
        {
            var entity = await _dbSet.FindAsync(id);
            if (entity != null)
            {
                _dbSet.Remove(entity);
                return true;
            }
            return false;
        }

        #endregion
    }
}
