# Presenting SentinelAI privacy redaction

## Two-minute demonstration

1. Start the local backend with the updated Python files. Build from the repository root with `npm --prefix extension run build`. Load or reload `extension/dist` in Chrome and refresh the Gmail tab so the new content script attaches.
2. Paste the [synthetic demonstration email](privacy-demo-email.txt) into a new draft. Open the SentinelAI pill. The tested draft produces **16 findings across 16 categories**, one checked occurrence per category.
3. Choose **Deselect all**, check just the address, and click **Redact selected**. The sentence becomes “I live in [ADDRESS].” Click **Undo** to restore the original.
4. Click **Redact all** on the original draft. Every automatic match gets its category placeholder. The greeting, closing and text around the address survive.
5. In a separate draft enter `Aadhaar: 2345 6789 0122` and `Phone: 1234567890` on separate lines. Both appear in the badge count, and both start unchecked. Redact all is disabled when the draft contains only unchecked review items. Checking an occurrence, a category or **Select all** explicitly selects the corresponding review items. After a draft edit, the scanner recalculates the ranges and resets selection.

The badge counts all findings. Automatic findings have enough format or contextual evidence to preselect. Review findings need a user's choice. No check here verifies that a person owns an identifier, that a number is assigned or that an address exists. A local detection service handles drafts. The compose preview receives masked findings and character positions. The redaction audit records counts.

## How to explain the sixteen categories

| Category | Evidence and context |
|---|---|
| Email | An email-shaped local part, domain and alphabetic suffix at a token boundary. No label required. |
| Phone | The local phonenumbers library checks the numbering plan. National numbers use the selected region (India by default), while international formats use their dialling code. A phone label or valid explicit plus prefix supports automatic redaction. Ambiguous bare Indian fixed lines and phone-shaped unlabelled national numbers go to review. A mobile label also checks the number type. |
| Aadhaar | An Aadhaar, Aadhar or UIDAI label, twelve digits beginning with 2–9, optional group separators and a valid Verhoeff checksum qualify. An unlabelled checksum-valid candidate or a labelled numeric value that fails validation can go to review. Ordinary IDs, quantities and arithmetic have additional exclusions. |
| Residential or mailing address | A local component parser checks the span and its residential context. Qualifying US mailing lines also use the optional usaddress parser. See the examples below. |
| Postal or ZIP code | A PIN code, postal code, postcode or ZIP label followed by a supported numeric, dashed or alphanumeric format. This validates shape. A code inside a complete address can be part of its single address finding. |
| US Social Security number | The labelled pattern accepts a structured nine-digit number, optionally dashed, and excludes disallowed area and zero groups. An unlabelled valid-shaped dashed SSN goes to review. |
| Bank account | A bank, savings or checking account label plus 8–18 digits with optional spaces or hyphens. Format and context only. |
| IFSC | An IFSC label and the eleven-character structure of four letters, zero and six alphanumeric characters. |
| IBAN | A labelled candidate is compacted and checked using python-stdnum's country-specific IBAN validation and checksum. An unlabelled compact candidate that passes goes to review. |
| Credit or debit card | Card context, 13–19 digits and the Luhn checksum, with additional exclusions for repeated digits and a leading zero. An unlabelled grouped 16-digit candidate can go to review. |
| Indian PAN | A PAN label plus the five-letter, four-digit and final-letter structure, including a recognized holder-type letter. |
| Passport | A passport label and a colon or equals sign, followed by 6–12 alphanumeric characters including a digit. Coverage is a generic format check. |
| UPI ID | A UPI, UPI ID or VPA label, colon or equals sign, and a structured handle with an @ and provider. |
| Password | Explicit password, passwd or passphrase assignment. Quoted values can contain spaces. Several common status words are excluded for unquoted values. |
| API key or client secret | Explicit API-key or client-secret assignment and a contiguous value of 12–512 allowed characters. Demo values are fictional. |
| Authentication token | Bearer syntax or an explicit token assignment with a 12–1,024 character value. A recognized three-segment JWT shape can also match without a label. The detector checks structure only. |

## Address recognition and boundaries

The parser looks for a locator such as a flat, apartment, numbered house or street, plot, block, tower, sector or PO box. In residential context it can also start at a named building, village or district. It extends the original character span across adjacent components, using commas, single line breaks, spaces, postal-code formats and connectors such as *at*, *near* and *in*. A numbered road, named building, colony, locality, landmark, city, state or postal code can corroborate the locator. A bare place name never starts an automatic address by itself. A whole sector and city can still be too broad to identify a residence.

A house number, explicit label, street name, city, state and postal code are each optional across the supported formats. A numbered street with a residential label can qualify alone. A flat alone normally needs a second component. A building and a unit can qualify without a street or postal code. US-style lines can additionally be recognized by the existing trained usaddress parser. All processing runs locally.

### Automatically redacted in the installed extension

| Synthetic input | What the address replacement covers |
|---|---|
| Address: Flat 402, Example Apartments, Road No. 5, Hyderabad, Telangana 500032 | Everything after the label |
| Flat 402, Example Apartments, Road No. 5, Hyderabad, Telangana 500032 | The complete address |
| I live in Flat 402 at Example Apartments near Sample Park in Hyderabad. | From “Flat” through “Hyderabad”, preserving the sentence punctuation |
| H.No. 12-34/5, Sample Colony, Hyderabad, Telangana | House identifier, colony, city and state |
| Plot No. 45, Road No. 10, Example Nagar, Hyderabad | Plot, numbered road, locality and city |
| Flat 302, Example Residency, near Sample Park, Hyderabad | Flat, building, landmark and city |
| 123 Example Street, Apartment 5, London, SW1A 1AA | Street through UK postcode |
| Flat 204, Example Residency, Sample Road, Hyderabad | Flat through city with no PIN |
| Block B, Tower 3, Willow Enclave, Sector 12, Jaipur | Block through city |
| Deliver to Willow Gardens, block D, Pune. | Named community through city |
| My home is Fern Village, Vale District. | Village and district |
| 12 Cedar Road, Toronto, ON M5V 2T6 | Street through Canadian postal code |
| flat no. 9b, willow residency, hill road, pune | Entire lowercase address |
| Home address: 17 Copper Road. Bring a snack. | Only “17 Copper Road” |
| Flat 12 Briar Apartments Road No. 3 Pune Maharashtra 411001 | Entire address, with no commas |

This multiline draft produced one address finding across all five lines:

```text
Flat 402
Example Apartments
Road No. 5
Hyderabad, Telangana
500032
```

### Review and limitations

`Flat 402`, `25 Cedar Street`, `P.O. Box 52`, `Block C` and `Sector 8, Jaipur` each produced one unchecked review item. “I live in Hyderabad.”, “We visited London last year.” and “The school is located near a park.” produced zero findings.

The contextual rules target English-language and transliterated address conventions. Local-script addresses, unfamiliar abbreviations, country-specific street prefixes, place names with unusual punctuation, directions with no recognizable locator and unconventional multiline layouts can be missed or only partially captured. A labelled numeric free-form address can go to review. Ambiguous adjoining prose can resemble a short place name. Check the preview when the exact boundary matters. The examples measure fixture behavior, not an overall accuracy rate.

## Root cause and verification

The reported Aadhaar value fails Verhoeff. The phone library accepts the second example as an Indian fixed-line numbering-plan pattern, but the detector treats its bare national digits as ambiguous. Both came back as review items with the expected offsets and validation codes. The previous compiled extension replaced both on **Redact all** despite their unchecked boxes. The fix limits that action to automatic findings plus explicitly selected review items. **Redact selected** continues to use only checked occurrences, including individually approved review items.

Testing used an installed unpacked extension, its actual background messaging bridge, a local backend with temporary SQLite databases, and a synthetic Gmail editor in a disposable Chrome profile. The tests checked the original bulk-redaction failure, selections before edits, the resulting draft, accurate counts, rich-text boundaries, Undo and the complete demo. Live Gmail and OAuth were outside the fixture run.

## Previous behavior at 4103e55

The API, Privacy tab and current Gmail compose build shared one Python detector. The extension's background script returned the local API's findings with their confidence, ambiguity, validation code and offsets intact. The older JavaScript files in the extension root were outside the Vite build. Both source and compiled compose code selected the two review-only numbers correctly on preview (unchecked), then the Redact all handler ignored that selection.

Address recognition used four paths, with no spaCy or general-purpose location model.

- A label (address, home address, residential address, mailing address or shipping address) followed by “is”, a colon or an equals sign accepted 8–180 characters containing a digit and two consecutive ASCII letters. It required no street, city, state or postal code. Commas were allowed. Capture stopped at a newline, semicolon, end of input or certain following field labels. This could capture unrelated prose on the same line.
- An unlabelled 1–6 digit house number, one to five words and an English street suffix produced a review-only street fragment, including inside a sentence. A P.O. Box and its number also produced a review item.
- For an entire US-style line, the detector first required an initial house number or PO Box, a two-letter state and a five-digit or ZIP+4 code. The optional local usaddress conditional random field parser then had to identify city, state, ZIP and either street name and house number or a box ID.
- A separate two-line US pattern applied the same parser when the locality, state and ZIP occupied the second line. Arbitrary line wrapping failed this prefilter. Indian or other international addresses could pass the generic labelled rule, but there was no Indian component parser. In the nine supplied fixtures the labelled address succeeded, the London street alone went to review, and the other seven produced no address.

## Verification record

| Check | Result |
|---|---|
| Existing Python suite plus four new address tests | 43 passed |
| Existing sensitive detection / numeric false-positive / compose interaction checks in installed Chrome | 21 / 12 / 16 passed |
| Installed compose address cases with exact span and resulting draft checks | 18 automatic replacements, 9 examples with zero findings, 5 unchecked review examples passed |
| Presentation email | 16 category groups, 16 checked occurrences, full redaction and Undo passed |
| Built artifact comparison | Only `extension/dist/content.js` differed from the original working bundle |

The implementation files are `privacy_detector.py`, `residential_addresses.py`, `extension/src/content/composePrivacy.js` and its generated `extension/dist/content.js`. The reproducible tests are in `tests/test_residential_addresses.py` and `tests/browser_smoke.py`. The launch instructions and presentation materials are in `README.md`, `docs/privacy-demo.md` and `docs/privacy-demo-email.txt`.
