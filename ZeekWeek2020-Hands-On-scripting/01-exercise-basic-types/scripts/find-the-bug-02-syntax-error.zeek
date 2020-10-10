module trainings;

export { 
global sport: 22/tcp ; 
} 

event zeek_init()
{

	if (sport < 1024/tcp )
		print fmt ("%s is in well-known ports", sport); 
} 

