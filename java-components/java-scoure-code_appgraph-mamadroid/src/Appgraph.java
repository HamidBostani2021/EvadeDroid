import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.io.File;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.PrintStream;
import java.util.regex.Pattern;
import org.xmlpull.v1.XmlPullParserException;

import fj.data.Option;

import java.lang.System;
import soot.PackManager;
import soot.Scene;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.solver.cfg.InfoflowCFG;
import soot.jimple.infoflow.source.data.SourceSinkDefinition;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.options.Options;

import soot.jimple.infoflow.android.axml.*;
import soot.jimple.infoflow.android.callbacks.CallbackDefinition;
import soot.jimple.infoflow.android.manifest.ProcessManifest;

import org.apache.commons.io.FilenameUtils;

public class Appgraph {	

	private static String appToRun = "";

	public static String androidPlatform = "";
	
	private static String output_dir = "";
	private static String jar_path = "";
	    
	public static void main(String[] args) {
		
		appToRun = args[0];
		androidPlatform = args[1];
		output_dir = args[2];
		jar_path = args[3];
		
		
		
		String filename = output_dir + FilenameUtils.getBaseName(appToRun) + ".txt";
		List<String> toInclude = Arrays.asList("java.", "android.", "org.", "com.", "javax.");
		List<String> toExclude = Arrays.asList("soot.");
		soot.G.reset();
		
		//String androidJarPath = Scene.v().getAndroidJarPath(androidPlatform, appToRun);
		SetupApplication app = new SetupApplication(androidPlatform + "/android-23/android.jar", appToRun);
		//SetupApplication app = new SetupApplication(androidPlatform, appToRun);
		//SetupApplication app = new SetupApplication(androidJarPath, appToRun);
		
		app.getConfig().setEnableStaticFieldTracking(false); //no static field tracking --nostatic
		//app.getConfig().setAccessPathLength(1); // specify access path length
		
		app.getConfig().setFlowSensitiveAliasing(false); // alias flowin
		System.out.println("*****1******");
		try {	
			System.out.println("call back: " + app.getCallbackClasses());
			app.calculateSourcesSinksEntrypoints(jar_path + "SourcesAndSinks.txt");
			System.out.println("*****1.1******");
			System.out.println("call back: " + app.getCallbackClasses());
			System.out.println("*****1.15******");
		} catch (IOException e) {
			e.printStackTrace();
			System.out.println(e);
			System.out.println("*****1.55******");
		} catch (XmlPullParserException e) {
			e.printStackTrace();
			System.out.println("*****1.6******");
		} catch(Exception e) {
			
			System.out.println("*****1.7******");
			System.out.println(e);
		}
		System.out.println("*****2******");
		PackManager.v().getPack("cg");
		PackManager.v().getPack("jb");
		PackManager.v().getPack("wjap.cgg");
		Options.v().set_src_prec(Options.src_prec_apk);
		Options.v().set_process_dir(Collections.singletonList(appToRun));		
		//Options.v().set_android_jars(androidPlatform);		
		
		//Hamid
		Options.v().set_force_android_jar(androidPlatform + "/android-23/android.jar");		
		
		System.out.println("*****3******");
		Options.v().set_whole_program(true);
		Options.v().set_allow_phantom_refs(true);
		Options.v().set_prepend_classpath(true);
		Options.v().set_app(true);
		Options.v().set_include(toInclude);
		Options.v().set_exclude(toExclude);
		Options.v().set_output_format(Options.output_format_xml);
		//Options.v().set_soot_classpath("soot-trunk.jar:soot-infoflow.jar:soot-infoflow-android.jar:axml-2.0.jar:slf4j-simple-1.7.5.jar:slf4j-api-1.7.5.jar");
		Options.v().set_soot_classpath(jar_path);
		System.out.println("*****4******");
		Options.v().setPhaseOption("cg", "safe-newinstance:true");
		Options.v().setPhaseOption("cg.spark", "on");
		Options.v().setPhaseOption("wjap.cgg", "show-lib-meths:true");
		Options.v().setPhaseOption("jb", "use-original-names:true");
		System.out.println("*****5******");
		try {
			System.out.println("*****5.1******");
			System.out.println("call back: " + app.getCallbackClasses());
			Scene.v().loadNecessaryClasses();
		}
		catch(Exception e) {
			System.out.println("*****5.5******" + e.toString());
			return;
		}
		
		System.out.println("*****6******");
		System.out.println("*****7******");
		System.out.println(app.getEntryPointCreator());
		SootMethod entryPoint = app.getEntryPointCreator().createDummyMain();
		System.out.println("*****7.5******");
		Options.v().set_main_class(entryPoint.getSignature());
		Scene.v().setEntryPoints(Collections.singletonList(entryPoint));
		
		System.out.println(entryPoint.getActiveBody());
		
		try {
			PackManager.v().runPacks();
		}
		catch (Exception f){
			f.printStackTrace();
		}
		try (BufferedWriter writer = new BufferedWriter(
				new FileWriter(
						new File(filename)))
		){			
			writer.write(Scene.v().getCallGraph().toString());
			System.out.println("call graph was extracted successfully");
		}
		catch (IOException e){
			System.out.println("An error occurred");
		}
	}
}
