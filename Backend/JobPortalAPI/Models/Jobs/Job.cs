using System.ComponentModel.DataAnnotations;

namespace JobPortalAPI;

public class Job
{
        [Key] 
        [Required]
        public int Id { get; set; } // Unique identifier
          [Required]
        public string Title { get; set; } = string.Empty;     
         [Required]
        public string Description  { get; set; } = string.Empty;      
         [Required]
        public string Location { get; set; } =string.Empty;
         [Required]
        public string Company { get; set; }   =string.Empty ;
         [Required]      
        public DateTime PostedDate { get; set; }
        
        }
