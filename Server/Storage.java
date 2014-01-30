package ssl;

public class Storage {

	int session_id;
	public byte S[] = new byte[32];
	
	Storage()
	{
		session_id = 1000;
	}
	
	public void new_session_id()
	{
		session_id++;
	}
	
}
