package hig.no.smartid;

import hig.no.smartid.lds.DG_COM;
import hig.no.smartid.service.BasicService;
import hig.no.smartid.service.SmartID;
import hig.no.smartid.service.Reader;
import hig.no.smartid.service.SecurityProvider;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;



import net.sourceforge.scuba.smartcards.CardServiceException;
import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.annotation.TargetApi;
import android.app.Activity;
import android.content.Intent;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Log;
import android.view.KeyEvent;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.inputmethod.EditorInfo;
import android.widget.EditText;
import android.widget.TextView;
import android.os.Build;

public class PasswdEnterActivity extends Activity {

	private static final String TAG = "SmartID";

	public final static String EXTRA_INFO = "hig.no.smartid";

	private BasicService basicService = null;

	private Reader reader = null;

	private String mPassword;

	// UI references.
	private EditText mPasswordView;
	private View mLoginFormView;
	private View mLoginStatusView;
	private TextView mLoginStatusMessageView;

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_passwd_enter);

		// Security.addProvider(new
		// org.bouncycastle.jce.provider.BouncyCastleProvider());
		// Locale.setDefault(Locale.ENGLISH);
		Security.addProvider(new SecurityProvider("myProv", 1, "hi"));

		// Set up the form.

		mPasswordView = (EditText) findViewById(R.id.password);

		mPasswordView
				.setOnEditorActionListener(new TextView.OnEditorActionListener() {
					@Override
					public boolean onEditorAction(TextView textView, int id,
							KeyEvent keyEvent) {
						if (id == R.id.login || id == EditorInfo.IME_NULL) {
							// attemptLogin();
							return true;
						}
						return false;
					}
				});

		mLoginFormView = findViewById(R.id.login_form);
		mLoginStatusView = findViewById(R.id.login_status);
		mLoginStatusMessageView = (TextView) findViewById(R.id.login_status_message);

		findViewById(R.id.sign_in_button).setOnClickListener(
				new View.OnClickListener() {
					@Override
					public void onClick(View view) {
						attemptLogin();
						//mPassword = mPasswordView.getText().toString();
						//ReadCard();
						//startActivity(new Intent(PasswdEnterActivity.this, MainActivity.class));

					}
				});

		// NFC
		Tag t = getIntent().getExtras().getParcelable(NfcAdapter.EXTRA_TAG);
		try {
			
			basicService = new BasicService(IsoDep.get(t));
			reader = new Reader();
			basicService.open();

		} catch (CardServiceException e) {
			e.printStackTrace();
		}

	}

	private byte[] getKeySeed(String passwd) {
		byte[] bacValue = new byte[16];
		try {
			MessageDigest md = MessageDigest.getInstance("SHA1");
			byte[] t = md.digest(passwd.getBytes());
			System.arraycopy(t, 0, bacValue, 0, 16);
		} catch (NoSuchAlgorithmException nsae) {
		}
		return bacValue;
	}

	public void ReadCard() {
		Log.v(TAG,"Inserted passwd manager card.");
		long timeElapsed = 0;
		try {
			byte[] s = getKeySeed(mPassword);
			if (s != null) {

				basicService.doBAC(s);
			}

			if (s != null) {
				Log.v(TAG, "setBACOK()");
			} else {
				Log.v(TAG, "setBACNotChecked()");
			}

			reader.setSmartID(new SmartID(basicService));
			
			if (reader.getSmartID().hasEAC()) {
				if (reader.getSmartID().wasEACPerformed()) {
					Log.v(TAG, "setEACOK()");
				} else {
					Log.v(TAG, "setEACFail()");
				}
			} else {
				Log.v(TAG, "setEACNotChecked()");
			}

			if (reader.getCOMFile() == null) {
				InputStream in = reader.getSmartID().getInputStream(
						BasicService.EF_COM);
				Log.i(TAG, "readCOM");
				reader.setCOMFile(new DG_COM(in));
				Log.i(TAG, "setCOM");
				reader.readData();
				Log.i(TAG, "read data ok");
				//reader.verifySecurity(basicService);
				//Log.i(TAG, "verify Security ok");
			}
		} catch (CardServiceException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		timeElapsed = System.currentTimeMillis() - timeElapsed;
        Log.v("Reading time: ",(timeElapsed / 1000)+ " s.");
	}

	// Called when the user clicks the Send button
	public void sendMessage(View view) {
		Intent intent = new Intent(this, MainActivity.class);
		String passwd = mPasswordView.getText().toString();
		intent.putExtra(EXTRA_INFO, passwd);
		startActivity(intent);
	}

	public void attemptLogin() {
		// Reset errors.

		mPasswordView.setError(null);

		// Store values at the time of the login attempt.

		mPassword = mPasswordView.getText().toString();

		boolean cancel = false;
		View focusView = null;

		// Check for a valid password.
		if (TextUtils.isEmpty(mPassword)) {
			mPasswordView.setError(getString(R.string.error_field_required));
			focusView = mPasswordView;
			cancel = true;
		} else if (mPassword.length() < 6) {
			mPasswordView.setError(getString(R.string.error_invalid_password));
			focusView = mPasswordView;
			cancel = true;
		}

		if (cancel) {
			// There was an error; don't attempt login and focus the first
			// form field with an error.
			focusView.requestFocus();
		} else {
			

			mLoginStatusMessageView.setText(R.string.enter1);
			showProgress(true);
			ReadCard();
			//sendMessage(mPasswordView);
			Intent intent = new Intent(this, MainActivity.class);
			
			intent.putExtra("sur", reader.getSur()); 
	        intent.putExtra("given", reader.getGiven());  
	        intent.putExtra("gender", reader.getGender());  
	        intent.putExtra("dob", reader.getDOB());  
	        intent.putExtra("pob", reader.getPOB());
	        intent.putExtra("doi", reader.getDOI()); 
	        intent.putExtra("doe", reader.getDOE());  
	        intent.putExtra("ic", reader.getIC());  
	        intent.putExtra("ia", reader.getIA());  
	        intent.putExtra("pn", reader.getPN());
	        
			startActivity(intent);
			
			
		}
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {

		// Inflate the menu; this adds items to the action bar if it is present.
		// getMenuInflater().inflate(R.menu.passwd_enter, menu);
		return true;
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		// Handle action bar item clicks here. The action bar will
		// automatically handle clicks on the Home/Up button, so long
		// as you specify a parent activity in AndroidManifest.xml.
		// int id = item.getItemId();
		// if (id == R.id.action_settings) {
		// return true;
		// }
		return super.onOptionsItemSelected(item);
	}

	/**
	 * Shows the progress UI and hides the login form.
	 */
	@TargetApi(Build.VERSION_CODES.HONEYCOMB_MR2)
	private void showProgress(final boolean show) {
		// On Honeycomb MR2 we have the ViewPropertyAnimator APIs, which allow
		// for very easy animations. If available, use these APIs to fade-in
		// the progress spinner.
		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.HONEYCOMB_MR2) {
			int shortAnimTime = getResources().getInteger(
					android.R.integer.config_mediumAnimTime);

			mLoginStatusView.setVisibility(View.VISIBLE);
			mLoginStatusView.animate().setDuration(shortAnimTime)
					.alpha(show ? 1 : 0)
					.setListener(new AnimatorListenerAdapter() {
						@Override
						public void onAnimationEnd(Animator animation) {
							mLoginStatusView.setVisibility(show ? View.VISIBLE
									: View.GONE);
						}
					});

			mLoginFormView.setVisibility(View.VISIBLE);
			mLoginFormView.animate().setDuration(shortAnimTime)
					.alpha(show ? 0 : 1)
					.setListener(new AnimatorListenerAdapter() {
						@Override
						public void onAnimationEnd(Animator animation) {
							mLoginFormView.setVisibility(show ? View.GONE
									: View.VISIBLE);
						}
					});
		} else {
			// The ViewPropertyAnimator APIs are not available, so simply show
			// and hide the relevant UI components.
			mLoginStatusView.setVisibility(show ? View.VISIBLE : View.GONE);
			mLoginFormView.setVisibility(show ? View.GONE : View.VISIBLE);
		}
	}

}
