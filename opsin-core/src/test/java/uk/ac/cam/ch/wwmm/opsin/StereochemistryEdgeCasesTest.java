package uk.ac.cam.ch.wwmm.opsin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import uk.ac.cam.ch.wwmm.opsin.OpsinResult.OPSIN_RESULT_STATUS;
import uk.ac.cam.ch.wwmm.opsin.OpsinWarning.OpsinWarningType;

public class StereochemistryEdgeCasesTest {

	@ParameterizedTest
	@ValueSource(strings = {
		"cis-hepta-2,4-diene", "trans-hepta-2,4-diene",
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
