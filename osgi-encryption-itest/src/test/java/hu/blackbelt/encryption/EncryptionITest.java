package hu.blackbelt.encryption;


import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.ops4j.pax.exam.Configuration;
import org.ops4j.pax.exam.Option;
import org.ops4j.pax.exam.junit.PaxExam;
import org.ops4j.pax.exam.spi.reactors.ExamReactorStrategy;
import org.ops4j.pax.exam.spi.reactors.PerClass;
import org.osgi.framework.BundleContext;
import org.osgi.service.log.LogService;

import javax.inject.Inject;
import java.io.*;
import java.net.MalformedURLException;


import static org.ops4j.pax.exam.CoreOptions.maven;
import static org.ops4j.pax.exam.CoreOptions.mavenBundle;
import static org.ops4j.pax.exam.OptionUtils.combine;
import static org.ops4j.pax.exam.karaf.options.KarafDistributionOption.editConfigurationFilePut;
import static org.ops4j.pax.exam.karaf.options.KarafDistributionOption.features;

@RunWith(PaxExam.class)
@ExamReactorStrategy(PerClass.class)
public class EncryptionITest {

    @Inject
    LogService log;

    @Inject
    BundleContext bundleContext;


    @Rule
    public ExpectedException thrown = ExpectedException.none();


    @Configuration
    public Option[] config() throws MalformedURLException {


        return combine(KarafFeatureProvider.karafConfig(this.getClass()),
                features(maven()
                                .groupId("hu.blackbelt")
                                .artifactId("osgi-encryption-karaf-feature")
                                .versionAsInProject()
                                .classifier("features")
                                .type("xml"),
                        "osgi-encryption")
        );


    }

    @Test
    public void testEncryption() throws IOException {
        Assert.assertTrue(true);
    }


}