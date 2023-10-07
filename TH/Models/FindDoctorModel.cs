namespace TH.Models
{
    public class FindDoctorModel : BaseModel
    {
        public List<IndividualDoctorModel> doctors { get; set; }
        public FindDoctorModel()
        {
            doctors = new List<IndividualDoctorModel>();
        }
    }


    public class IndividualDoctorModel : BaseModel
    {
        public string Name { get; set; } = string.Empty;
        public string profileImageLink { get; set; } = string.Empty;
    }
}
