package tia.example.oauth2;

import org.apache.catalina.Context;
import org.apache.catalina.WebResourceRoot;
import org.apache.catalina.WebResourceSet;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.webresources.DirResourceSet;
import org.apache.catalina.webresources.JarResourceSet;
import org.apache.catalina.webresources.StandardRoot;

import java.io.File;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;
import java.util.logging.FileHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

public class Main {

    private static final String WEBAPP_DIR_LOCATION = "src/main/webapp/";
    private static final String WEB_APP_NAME = "oidc-cmj-web";

    public static void main(String[] args) throws Exception {

        Logger logger = Logger.getLogger("");
        //logger.setLevel(Level.FINE);

        Handler fileHandler = new FileHandler("catalina.log", true);
        fileHandler.setFormatter(new SimpleFormatter());
        fileHandler.setLevel(Level.ALL);
        fileHandler.setEncoding("UTF-8");
        logger.addHandler(fileHandler);

        Path tempPath = Paths.get(System.getProperty("java.io.tmpdir"), WEB_APP_NAME);

        File workFolder = getRootFolder();
        System.setProperty("org.apache.catalina.startup.EXIT_ON_INIT_FAILURE", "true");
        Tomcat tomcat = new Tomcat();

        //The port that we should run on can be set into an environment variable
        //Look for that variable and default to 8081 if it isn't there.
        String webPort = Optional.ofNullable(System.getenv("PORT")).orElse("8081");
        tomcat.setPort(Integer.parseInt(webPort));
        //ctx.setAddWebinfClassesResources(true); // process /META-INF/resources for static

        // Declare an alternative location for your "WEB-INF/classes" dir
        // Servlet 3.0 annotation will work
        File additionWebInfClassesFolder = new File(workFolder.getAbsolutePath(), "target/classes");

        String base = "";
        URL main = Main.class.getResource("Main.class");
        String path = main.getPath();
        logger.info("Main path: " + path);

        WebResourceSet resourceSet;
        Context ctx;
        WebResourceRoot resourceRoot;
        if (additionWebInfClassesFolder.exists()) {
            File webContentFolder = new File(workFolder.getAbsolutePath(), WEBAPP_DIR_LOCATION);
            ctx = tomcat.addWebapp('/' + WEB_APP_NAME, webContentFolder.getAbsolutePath());
            resourceRoot = new StandardRoot(ctx);
            resourceSet = new DirResourceSet(resourceRoot, "/WEB-INF/classes", additionWebInfClassesFolder.getAbsolutePath(), "/");
            resourceRoot.addJarResources(resourceSet);
            logger.info("loading WEB-INF resources from as '" + additionWebInfClassesFolder.getAbsolutePath() + "'");
            logger.info("configuring app with basedir: " + webContentFolder.getAbsolutePath());
        } else {

            if ("jar".equals(main.getProtocol())) {
                base = path.substring(path.indexOf(':') + 1, path.indexOf('!'));
            } else if ("file".equals(main.getProtocol())) {
                base = workFolder.getAbsolutePath();
            }
            //Path tempPath = Files.createTempDirectory("tomcat-base-dir");
            tempPath.toFile().deleteOnExit();
            tomcat.setBaseDir(tempPath.toString());
            File docBase = new File(tempPath.toString(), "webapps");
            docBase.mkdirs();
            logger.info("Tomcat docBase: " + docBase.getAbsolutePath());
            //Context ctx = tomcat.addWebapp('/' + WEB_APP_NAME, base + "/oidc-cmj-web.war");
            //ctx = tomcat.addWebapp('/' + WEB_APP_NAME, ".");
            ctx = tomcat.addWebapp('/' + WEB_APP_NAME, docBase.getAbsolutePath());

            resourceRoot = new StandardRoot(ctx);
            resourceSet = new JarResourceSet(resourceRoot, "/WEB-INF/classes",
                    base, "/");
            logger.info("loading WEB-INF resources from as '" + base + "'");
            resourceRoot.addJarResources(resourceSet);

        }
        //Set execution independent of current thread context classloader (compatibility with exec:java mojo)
        ctx.setParentClassLoader(Main.class.getClassLoader());
        ctx.setResources(resourceRoot);
        // fix Illegal reflective access by org.apache.catalina.loader.WebappClassLoaderBase
        // https://github.com/spring-projects/spring-boot/issues/15101#issuecomment-437384942
        /*StandardContext standardContext = (StandardContext) ctx;
        standardContext.setClearReferencesObjectStreamClassCaches(false);
        standardContext.setClearReferencesRmiTargets(false);
        standardContext.setClearReferencesThreadLocals(false);*/

        // prevent register jsp servlet
        //tomcat.setAddDefaultWebXmlToWebapp(false);
        //tomcat.initWebappDefaults(ctx);

        tomcat.getConnector(); // Start http listener. Having to call this looks like a bug
        tomcat.start();
        tomcat.getServer().await();
        tempPath.toFile().delete();
    }

    private static File getRootFolder() {
        try {
            File root;
            String runningJarPath = Main.class.getProtectionDomain().getCodeSource().getLocation().toURI().getPath().replaceAll("\\\\", "/");
            int lastIndexOf = runningJarPath.lastIndexOf("/target/");
            if (lastIndexOf < 0) {
                root = new File("");
            } else {
                root = new File(runningJarPath.substring(0, lastIndexOf) + "/target");
            }
            System.out.println("application resolved root folder: " + root.getAbsolutePath());
            return root;
        } catch (URISyntaxException ex) {
            throw new RuntimeException(ex);
        }
    }
}