package hig.no.smartid;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.ImageView;
import android.widget.TextView;

public class MainActivity extends Activity {
	
	private ImageView pic;
	
	private TextView sur;
	private TextView given;
	private TextView gender;
	private TextView dob;
	private TextView pob;
	private TextView doi;
	private TextView doe;
	private TextView ic;
	private TextView ia;
	private TextView pn;
	
	
	private TextView com;

	private TextView bac;
	private TextView eac;
	private TextView aa;
	private TextView pa;
	
	private void initial() {
		
		pic = (ImageView) findViewById(R.id.pic);

		sur = (TextView) findViewById(R.id.sur);
		given = (TextView) findViewById(R.id.given);
		gender = (TextView) findViewById(R.id.gender);
		dob = (TextView) findViewById(R.id.dob);
		pob = (TextView) findViewById(R.id.pob);
		doi = (TextView) findViewById(R.id.doi);
		doe = (TextView) findViewById(R.id.doe);
		ic = (TextView) findViewById(R.id.ic);
		ia = (TextView) findViewById(R.id.ia);
		pn = (TextView) findViewById(R.id.pn);
		
		com = (TextView) findViewById(R.id.com);

		bac = (TextView) findViewById(R.id.BAC);
		eac = (TextView) findViewById(R.id.EAC);
		aa = (TextView) findViewById(R.id.AA);
		pa = (TextView) findViewById(R.id.PA);

		bac.setTextColor(Color.GREEN);
		eac.setTextColor(Color.RED);
		aa.setTextColor(Color.RED);
		pa.setTextColor(Color.RED);

	}

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);

		initial();
		
		pic.setImageResource(R.drawable.ic_launcher);
		
		// Get the message from the intent  
        Intent intent = getIntent(); 
        
        String SUR = intent.getStringExtra("sur"); 
        String GIVEN = intent.getStringExtra("given");  
        String GENDER = intent.getStringExtra("gender");  
        String DOB = intent.getStringExtra("dob");  
        String POB = intent.getStringExtra("pob");
        String DOI = intent.getStringExtra("doi"); 
        String DOE = intent.getStringExtra("doe");  
        String IC = intent.getStringExtra("ic");  
        String IA = intent.getStringExtra("ia");  
        String PN = intent.getStringExtra("pn");
        
        sur.setText(SUR);
        given.setText(GIVEN);
        gender.setText(GENDER);
        dob.setText(DOB);
        pob.setText(POB);
        doi.setText(DOI);
        doe.setText(DOE);
        ic.setText(IC);
        ia.setText(IA);
        pn.setText(PN);
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {

		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.main, menu);
		return true;
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		// Handle action bar item clicks here. The action bar will
		// automatically handle clicks on the Home/Up button, so long
		// as you specify a parent activity in AndroidManifest.xml.
		int id = item.getItemId();
		if (id == R.id.about) {
			return true;
		}
		return super.onOptionsItemSelected(item);
	}


}
