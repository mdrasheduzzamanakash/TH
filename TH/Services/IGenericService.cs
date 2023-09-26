namespace TH.Services
{
    public interface IGenericService<T> where T : class
    {
        Task<IEnumerable<T>> GetAllAsync();
        Task<T?> GetByIdAsync(int id);
        Task<T?> InsertAsync(T entity);
        Task<T?> UpdateAsync(T entity, int id);
        Task<bool> DeleteAsync(int id);

    }
}
