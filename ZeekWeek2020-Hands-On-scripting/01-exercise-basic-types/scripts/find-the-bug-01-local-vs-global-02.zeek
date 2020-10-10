module trainings;

global ip = 1.1.1.1; 
global sport = 22/tcp; 
global ssub = 1.1.1.0/24 ; 
global answer = F; 

event zeek_init()
{
	if (ip in ssub) 
	{ 
		answer= T; 
	} 
} 

module NewTraining; 

event zeek_done()
{

	print fmt("Answer that %s is in %s: %s", trainings::ip, trainings::ssub, trainings::answer); 
	print fmt (""); 
	print fmt (""); 
	print fmt ("==================================================="); 
	print fmt ("Remember scope of global, without export {},"); 
	print fmt ("is limited to until the next module starts.");
	print fmt ("Above isnt' sufficient hint still ;) there is more"); 
	print fmt ("This concept will help with you clusterize your scripts"); 
	print fmt ("==================================================="); 
} 


