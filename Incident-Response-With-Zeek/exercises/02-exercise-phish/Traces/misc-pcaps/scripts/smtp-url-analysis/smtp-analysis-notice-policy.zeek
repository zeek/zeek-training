hook Notice::policy(n: Notice::Info)
	{
	#if ( n$note == SMTPurl::BogusSiteURL)
	#{ add n$actions[Notice::ACTION_EMAIL];}

	if ( n$note == SMTPurl::WRITER_POSTGRESQL_CRASH )
		{
		add n$actions[Notice::ACTION_EMAIL];
		}

	#  if ( n$note == SMTPurl::AddressSpoofer )
	#   { add n$actions[Notice::ACTION_EMAIL];}

	#  if ( n$note == SMTPurl::NameSpoofer)
	#   { add n$actions[Notice::ACTION_EMAIL];}

	#  if ( n$note == SMTPurl::HistoricallyNewAttacker)
	#   { add n$actions[Notice::ACTION_EMAIL];}
	}
