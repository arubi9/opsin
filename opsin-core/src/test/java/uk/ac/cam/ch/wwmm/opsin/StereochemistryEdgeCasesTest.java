package uk.ac.cam.ch.wwmm.opsin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import uk.ac.cam.ch.wwmm.opsin.OpsinResult.OPSIN_RESULT_STATUS;
import uk.ac.cam.ch.wwmm.opsin.OpsinWarning.OpsinWarningType;

public class StereochemistryEdgeCasesTest {

	@ParameterizedTest
	@CsvSource(delimiter = '|', value = {
		"cis,cis-hexa-2,4-diene | (2Z,4Z)-hexa-2,4-diene | 2",
		"trans,trans-hexa-2,4-diene | (2E,4E)-hexa-2,4-diene | 2",
		"cis,cis-muconic acid | (2Z,4Z)-muconic acid | 2",
		"trans,trans-muconic acid | (2E,4E)-muconic acid | 2",
		"cis,cis-hepta-2,4-diene | (2Z,4Z)-hepta-2,4-diene | 2",
		"trans,trans-hepta-2,4-diene | (2E,4E)-hepta-2,4-diene | 2",
		"cis,cis,cis-octa-2,4,6-triene | (2Z,4Z,6Z)-octa-2,4,6-triene | 3",
		"trans,trans,trans-octa-2,4,6-triene | (2E,4E,6E)-octa-2,4,6-triene | 3",
		"cis,cis-2,3,5,6-tetrachlorohepta-2,5-diene | (2Z,5Z)-2,3,5,6-tetrachlorohepta-2,5-diene | 2",
		"trans,trans-2,3,5,6-tetrachlorohepta-2,5-diene | (2E,5E)-2,3,5,6-tetrachlorohepta-2,5-diene | 2",
		"(2E)-cis,cis-octa-2,4,6-triene | (2E,4Z,6Z)-octa-2,4,6-triene | 3",
		"(cis,cis)-hexa-2,4-diene | (2Z,4Z)-hexa-2,4-diene | 2"
	})
	public void repeatedIdenticalCisTransFullySpecifiesEligibleBonds(String name, String equivalentEZName, int stereoBondCount) {
		OpsinResult result = NameToStructure.getInstance().parseChemicalName(name);
		assertEquals(OPSIN_RESULT_STATUS.SUCCESS, result.getStatus(), result.getMessage());
		OpsinResult expected = NameToStructure.getInstance().parseChemicalName(equivalentEZName);
		assertEquals(OPSIN_RESULT_STATUS.SUCCESS, expected.getStatus(), expected.getMessage());
		assertEquals(expected.getSmiles(), result.getSmiles());
		assertEquals(stereoBondCount, result.getStructure().getBondSet().stream()
				.filter(bond -> bond.getBondStereo() != null).count());
	}

	@ParameterizedTest
	@ValueSource(strings = {
		"cis-hepta-2,4-diene", "trans-hepta-2,4-diene",
		"cis,cis-octa-2,4,6-triene", "trans,trans-octa-2,4,6-triene",
		"cis,trans-hepta-2,4-diene", "trans,cis-hepta-2,4-diene",
		"cis,cis,trans-nona-2,4,6-triene", "trans,trans,cis-nona-2,4,6-triene",
		"cis-2,3,5,6-tetrachlorohepta-2,5-diene",
		"trans-2,3,5,6-tetrachlorohepta-2,5-diene"
	})
	public void rejectUnlocantedCisTransWithMultipleEligibleBonds(String name) {
		OpsinResult result = NameToStructure.getInstance().parseChemicalName(name);
		assertEquals(OPSIN_RESULT_STATUS.FAILURE, result.getStatus(), result.getMessage());
		assertNull(result.getSmiles());
		assertTrue(result.getMessage().contains("More than one bond"), result.getMessage());
		assertTrue(result.getMessage().contains("locant"), result.getMessage());
	}

	@ParameterizedTest
	@ValueSource(strings = {"cis-hepta-2,4-diene", "trans-2,3,5,6-tetrachlorohepta-2,5-diene"})
	public void ignoredAmbiguousStereoRequiresExplicitOptInAndWarning(String name) {
		NameToStructureConfig config = new NameToStructureConfig();
		config.setWarnRatherThanFailOnUninterpretableStereochemistry(true);
		OpsinResult result = NameToStructure.getInstance().parseChemicalName(name, config);
		assertEquals(OPSIN_RESULT_STATUS.WARNING, result.getStatus());
		assertNotNull(result.getStructure());
		assertTrue(result.getWarnings().stream().anyMatch(w -> w.getType() == OpsinWarningType.STEREOCHEMISTRY_IGNORED));
		for (Bond bond : result.getStructure().getBondSet()) {
			assertNull(bond.getBondStereo(), "Ambiguous stereo must not be assigned to an arbitrary bond");
		}
	}

	@ParameterizedTest
	@ValueSource(strings = {"(2E,2Z)-but-2-ene", "(E)-(Z)-but-2-ene", "(E)-2-methylprop-1-ene",
		"cis-2-chlorobut-2-ene", "cis-2-bromo-3-chlorobut-2-ene", "(E/Z)-but-2-ene"})
	public void rejectConflictingInapplicableOrUnsupportedStereo(String name) {
		OpsinResult result = NameToStructure.getInstance().parseChemicalName(name);
		assertEquals(OPSIN_RESULT_STATUS.FAILURE, result.getStatus());
		assertNull(result.getSmiles());
		assertTrue(!result.getMessage().isEmpty());
	}

	@ParameterizedTest
	@ValueSource(strings = {"cis-9-bromo-10-chloro-9-octadecene", "trans-9-bromo-10-chloro-9-octadecene"})
	public void reportStereoFailureInsteadOfEarlierLocantFailure(String name) {
		OpsinResult result = NameToStructure.getInstance().parseChemicalName(name);
		assertEquals(OPSIN_RESULT_STATUS.FAILURE, result.getStatus());
		assertTrue(result.getMessage().contains("could refer unambiguously"), result.getMessage());
	}

	@ParameterizedTest
	@ValueSource(strings = {"(EorZ)-but-2-ene", "(EZ)-but-2-ene"})
	public void unspecifiedGeometryDoesNotChooseAnIsomer(String name) {
		OpsinResult result = NameToStructure.getInstance().parseChemicalName(name);
		assertEquals(OPSIN_RESULT_STATUS.SUCCESS, result.getStatus(), result.getMessage());
		assertEquals("CC=CC", result.getSmiles());
		for (Bond bond : result.getStructure().getBondSet()) {
			assertNull(bond.getBondStereo());
		}
	}
}
