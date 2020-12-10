
        if check_key_id(&KYBER512, algorithm_id) {
            return Ok(&KYBER512);
        }

        if check_key_id(&LIGHTSABER, algorithm_id) {
            return Ok(&LIGHTSABER);
        }

        if check_key_id(&SIDHP434, algorithm_id) {
            return Ok(&SIDHP434);
        }
