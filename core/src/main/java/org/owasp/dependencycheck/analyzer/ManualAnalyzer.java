package org.owasp.dependencycheck.analyzer;

import java.io.File;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * ManualAnalyzer reads .dependencyproperties files which contain product,
 * vendor and version information for a dependency. It can be used where other
 * analyzers don't find enough evidence to determine the CPE (e.g., C++
 * libraries).
 * 
 * Such .dependencyproperties files can be added right where the libraries are
 * stored. They should be named like the library, and contain 3 properties
 * VENDOR, PRODUCT, VERSION. 
 * Example:
 * curl-7.20.1/curl-7.20.1.dependencyproperties: 
 * VENDOR=haxx 
 * PRODUCT=curl
 * VERSION=7.20.1
 * 
 */
@Experimental
public class ManualAnalyzer extends AbstractFileTypeAnalyzer {

	public static final String DEPENDENCY_ECOSYSTEM = "Manual";
	private static final Logger LOGGER = LoggerFactory.getLogger(ManualAnalyzer.class);
	private static final String FILE_EXTENSION = ".dependencyproperties";
	private static final FileFilter DEPENDENCY_FILTER = FileFilterBuilder.newInstance().addExtensions(FILE_EXTENSION)
			.build();

	@Override
	public String getName() {
		return "Manual Analyzer";
	}

	@Override
	public AnalysisPhase getAnalysisPhase() {
		return AnalysisPhase.INFORMATION_COLLECTION;
	}

	@Override
	protected FileFilter getFileFilter() {
		return DEPENDENCY_FILTER;
	}

	@Override
	protected void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {
		// nothing to do

	}

	/**
	 * Load properties from file and add any evidence found there to the dependency.
	 * 
	 * @see
	 * org.owasp.dependencycheck.analyzer.AbstractAnalyzer#analyzeDependency(org.
	 * owasp.dependencycheck.dependency.Dependency,
	 * org.owasp.dependencycheck.Engine)
	 */
	@Override
	protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
		dependency.setEcosystem(DEPENDENCY_ECOSYSTEM);

		// DisplayFileName will show up in the report -
		// we remove the file extension to get cleaner names there
		dependency.setDisplayFileName(dependency.getDisplayFileName().replace(FILE_EXTENSION, ""));

		final File dependencyFile = dependency.getActualFile();

		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(String.format("Analyzing dependency properties: %s ...", dependencyFile.getAbsolutePath()));
		}

		final Properties dependencyProperties = loadDependencyProperties(dependencyFile);
		addEvidence(dependency, EvidenceType.VENDOR, dependencyProperties);
		addEvidence(dependency, EvidenceType.PRODUCT, dependencyProperties);
		addEvidence(dependency, EvidenceType.VERSION, dependencyProperties);

		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(
					String.format("Finished analyzing dependency properties: %s.", dependencyFile.getAbsolutePath()));
		}

	}

	/**
	 * Load dependency properties from file.
	 *
	 * @param dependencyFile the dependency file
	 * @return the properties
	 * @throws AnalysisException in case the dependency file can't be read
	 */
	private Properties loadDependencyProperties(File dependencyFile) throws AnalysisException {
		Properties properties = new Properties();
		try {
			properties.load(new FileInputStream(dependencyFile));
		} catch (IOException e) {
			throw new AnalysisException(String.format("Problem occurred while reading dependency file %s.",
					dependencyFile.getAbsolutePath()), e);
		}
		return properties;
	}

	/**
	 * Add an evidence if found in passed properties
	 *
	 * @param dependency the dependency
	 * @param type the evidence type (VENDOR, PRODUCT, or VERSION)
	 * @param properties the properties
	 */
	private void addEvidence(Dependency dependency, EvidenceType type, Properties properties) {
		String value = properties.getProperty(type.toString());
		if (value != null) {
			dependency.addEvidence(type, FILE_EXTENSION, type.toString(), value, Confidence.HIGHEST);
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug(String.format("Found %s evidence: %s", type.toString(), value));
			}
		}
	}

	@Override
	protected String getAnalyzerEnabledSettingKey() {
		return Settings.KEYS.ANALYZER_MANUAL_ENABLED;
	}

}
