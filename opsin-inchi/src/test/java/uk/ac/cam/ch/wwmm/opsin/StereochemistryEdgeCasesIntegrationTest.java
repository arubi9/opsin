package uk.ac.cam.ch.wwmm.opsin;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import uk.ac.cam.ch.wwmm.opsin.OpsinResult.OPSIN_RESULT_STATUS;

public class StereochemistryEdgeCasesIntegrationTest {

	// Fixed InChIs check bond positions, configuration and retained isotope/atom stereo,
	// rather than merely checking whether parsing produced a structure.
	@ParameterizedTest
	@CsvSource(delimiter = '|', value = {
		"Cis-9,10-dichloro-9-octadecene | InChI=1S/C18H34Cl2/c1-3-5-7-9-11-13-15-17(19)18(20)16-14-12-10-8-6-4-2/h3-16H2,1-2H3/b18-17-",
		"trans-9,10-dichloro-9-octadecene | InChI=1S/C18H34Cl2/c1-3-5-7-9-11-13-15-17(19)18(20)16-14-12-10-8-6-4-2/h3-16H2,1-2H3/b18-17+",
		"cis-2,3-diiodobut-2-ene | InChI=1S/C4H6I2/c1-3(5)4(2)6/h1-2H3/b4-3-",
		"trans-2,3-diiodobut-2-ene | InChI=1S/C4H6I2/c1-3(5)4(2)6/h1-2H3/b4-3+",
		"(2E,4Z)-hepta-2,4-diene | InChI=1S/C7H12/c1-3-5-7-6-4-2/h3,5-7H,4H2,1-2H3/b5-3+,7-6-",
		"(2Z,4E)-hepta-2,4-diene | InChI=1S/C7H12/c1-3-5-7-6-4-2/h3,5-7H,4H2,1-2H3/b5-3-,7-6+",
		"(2E)-cis-hepta-2,4-diene | InChI=1S/C7H12/c1-3-5-7-6-4-2/h3,5-7H,4H2,1-2H3/b5-3+,7-6-",
		"(2E)-trans-hepta-2,4-diene | InChI=1S/C7H12/c1-3-5-7-6-4-2/h3,5-7H,4H2,1-2H3/b5-3+,7-6+",
		"(2R)-trans-pent-3-en-2-ol | InChI=1S/C5H10O/c1-3-4-5(2)6/h3-6H,1-2H3/b4-3+/t5-/m1/s1",
		"(2R)-cis-pent-3-en-2-ol | InChI=1S/C5H10O/c1-3-4-5(2)6/h3-6H,1-2H3/b4-3-/t5-/m1/s1",
		"(2R,3E)-pent-3-en-2-ol | InChI=1S/C5H10O/c1-3-4-5(2)6/h3-6H,1-2H3/b4-3+/t5-/m1/s1",
		"(2R,3Z)-pent-3-en-2-ol | InChI=1S/C5H10O/c1-3-4-5(2)6/h3-6H,1-2H3/b4-3-/t5-/m1/s1",
		"cis-1,2-dimethylcyclohexane | InChI=1S/C8H16/c1-7-5-3-4-6-8(7)2/h7-8H,3-6H2,1-2H3/t7-,8+",
		"trans-1,2-dimethylcyclohexane | InChI=1S/C8H16/c1-7-5-3-4-6-8(7)2/h7-8H,3-6H2,1-2H3/t7-,8-/m1/s1",
		"(E)-cyclooctene | InChI=1S/C8H14/c1-2-4-6-8-7-5-3-1/h1-2H,3-8H2/b2-1+",
		"(Z)-cyclooctene | InChI=1S/C8H14/c1-2-4-6-8-7-5-3-1/h1-2H,3-8H2/b2-1-",
		"cis-2,3-dichloro(2-13C)but-2-ene | InChI=1S/C4H6Cl2/c1-3(5)4(2)6/h1-2H3/b4-3-/i3+1",
		"trans-2,3-dichloro(2-13C)but-2-ene | InChI=1S/C4H6Cl2/c1-3(5)4(2)6/h1-2H3/b4-3+/i3+1",
		"(E)-1-deuterioprop-1-ene | InChI=1S/C3H6/c1-3-2/h3H,1H2,2H3/i1D/b3-1+",
		"(Z)-1-deuterioprop-1-ene | InChI=1S/C3H6/c1-3-2/h3H,1H2,2H3/i1D/b3-1-",
		"(E)-2-bromobut-2-ene | InChI=1S/C4H7Br/c1-3-4(2)5/h3H,1-2H3/b4-3+",
		"(Z)-2-bromobut-2-ene | InChI=1S/C4H7Br/c1-3-4(2)5/h3H,1-2H3/b4-3-",
		"(EorZ)-but-2-ene | InChI=1S/C4H8/c1-3-4-2/h3-4H,1-2H3",
		"(EZ)-but-2-ene | InChI=1S/C4H8/c1-3-4-2/h3-4H,1-2H3"
	})
	public void preservesExpectedStereochemicalStructure(String name, String expectedInchi) {
		OpsinResult result = NameToStructure.getInstance().parseChemicalName(name);
		assertEquals(OPSIN_RESULT_STATUS.SUCCESS, result.getStatus(), result.getMessage());
		assertEquals(expectedInchi, NameToInchi.convertResultToStdInChI(result));
	}

	@ParameterizedTest
	@CsvSource(delimiter = '|', value = {
		"cis,cis-hexa-2,4-diene | (2Z,4Z)-hexa-2,4-diene",
		"trans,trans-hexa-2,4-diene | (2E,4E)-hexa-2,4-diene",
		"cis,cis-muconic acid | (2Z,4Z)-muconic acid",
		"trans,trans-muconic acid | (2E,4E)-muconic acid",
		"cis,cis-hepta-2,4-diene | (2Z,4Z)-hepta-2,4-diene",
		"trans,trans-hepta-2,4-diene | (2E,4E)-hepta-2,4-diene",
		"(2E)-cis,cis-octa-2,4,6-triene | (2E,4Z,6Z)-octa-2,4,6-triene"
	})
	public void repeatedCisTransPreservesAllDoubleBondConfigurations(String name, String equivalentEZName) {
		OpsinResult result = NameToStructure.getInstance().parseChemicalName(name);
		assertEquals(OPSIN_RESULT_STATUS.SUCCESS, result.getStatus(), result.getMessage());
		OpsinResult expected = NameToStructure.getInstance().parseChemicalName(equivalentEZName);
		assertEquals(OPSIN_RESULT_STATUS.SUCCESS, expected.getStatus(), expected.getMessage());
		assertEquals(NameToInchi.convertResultToStdInChI(expected), NameToInchi.convertResultToStdInChI(result));
	}

	@ParameterizedTest
	@ValueSource(strings = {"CIS-2,3-dichlorobut-2-ene", "cis–2,3-dichlorobut–2–ene",
		"  CIS–2,3-dichlorobut–2–ene  ", "(cis)-2,3-dichlorobut-2-ene"})
	public void formattingVariantsPreserveCisGeometry(String name) {
		OpsinResult result = NameToStructure.getInstance().parseChemicalName(name);
		assertEquals(OPSIN_RESULT_STATUS.SUCCESS, result.getStatus(), result.getMessage());
		assertEquals("InChI=1S/C4H6Cl2/c1-3(5)4(2)6/h1-2H3/b4-3-", NameToInchi.convertResultToStdInChI(result));
	}

	@ParameterizedTest
	@ValueSource(strings = {"(Z)-but-2-ene", "[Z]-but-2-ene", "  (Z)-but-2-ene  "})
	public void bracketsAndWhitespacePreserveZGeometry(String name) {
		OpsinResult result = NameToStructure.getInstance().parseChemicalName(name);
		assertEquals(OPSIN_RESULT_STATUS.SUCCESS, result.getStatus(), result.getMessage());
		assertEquals("InChI=1S/C4H8/c1-3-4-2/h3-4H,1-2H3/b4-3-", NameToInchi.convertResultToStdInChI(result));
	}
}
