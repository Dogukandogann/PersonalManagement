using BaseLibrary.Entities;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ServerLibrary.Data
{
    public class HrDbContext(DbContextOptions options) : DbContext(options)
    {
        public DbSet<Employee> Employees { get; set; }
        public DbSet<GeneralDepartment> GeneralDepartments { get; set; }
        public DbSet<Department> Departments { get; set; }
        public DbSet<Branch> Branchs { get; set; }
        public DbSet<Town> Towns { get; set; }
        public DbSet<AppUser> AppUsers { get; set; }
        public DbSet<UserRole> UserRoles { get; set; }
        public DbSet<SystemRole> SystemRoles { get; set; }
    }
}
