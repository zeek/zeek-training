# lliliiLlls

module 		lllililli;
	export 




{  global llil:
		set



		[


count




]={

0x00	,




}

					;
		type 


illlllliiili:




enum
		{




illlllliiiliii,
illlllliiiliiii,
illlllliiiliiiiiiii,
illlllliiiliiiiiiiil,




	};

  global 
illill:		table




[
string
			] 
                 	of 
 string
			=
			{
    			[
"Main"


			] 

= 

	"The majority of the episode is based on what this character does",


	[


"Comic Relief"

  ]

= 


"The major of bad fortune happens to this character through the episode",
    [
		"Build Up"
	] 		
	= 

																			"The first 1/3 of the episode is about this character and sets the stage for the last 2/3",
  }	
;

			# Oh boy, here we go!
		  	global
 llllii:
  vector 


	of 

string					=


{"Homer"
	,"Marge"
		,"Lisa"
			,"Bart"
				,"Maggie"
					,"Grandpa"
						,"Ned"
							,"Krusty"
								,"Dr. Hibbert"
									,"Moe"};

	  global
 lllli:



function(
		)	;	}

function lllililli::lllli(
	) 
{
  for (
lliliiLll 			in 
lllililli::illill

	) 
	{
    local 
i 
	 			 



				=0x0		
			    	;while 
	(
i
 				in 

lllililli::llil
	) 
{		srand

	(		double_to_count

		(		time_to_double

			(		current_time

				(


))))

;


      i 
= 
rand(
	|	
lllililli::llllii
	|
)	;
    	}
    
 add 
	
		lllililli::llil[
i

				]


;

    local        

		  iillliliiililil 


= 		lllililli::llllii[i];
    local         ililllllllllilii 

= 		lliliiLll;
    local    

		  liiiiliiiiiiiiii 

= lllililli::illill[lliliiLll]

  ;

    print 			fmt
	  (


"%s %s  %s%s   %s"




		
,    iillliliiililil   , " " 
,    ililllllllllilii  , " " , liiiiliiiiiiiiii


  )
	;
 
  }
  }

event				zeek_init
  (
  ) 	&priority


= 0x00

 {
		  lllililli::lllli




(							);

							}
