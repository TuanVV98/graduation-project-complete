package com.spring.controller.v1.voucher;

import com.spring.dto.model.VoucherDTO;
import com.spring.dto.response.Response;
import com.spring.exception.NotFoundException;
import com.spring.exception.NotParsableContentException;
import com.spring.model.Voucher;
import com.spring.service.voucher.VoucherService;
import com.spring.service.voucher.VoucherServiceImpl;
import com.spring.utils.ApiUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping(value = "/api/v1/vouchers")
public class VoucherController {

	private final VoucherService voucherService;

	@Autowired
	public VoucherController(VoucherService voucherService) {
		this.voucherService = voucherService;
	}

	@Autowired
	VoucherServiceImpl voucherServiceImpl;

	@PostMapping("/test")
	public ResponseEntity<Response<VoucherDTO>> getAll1(VoucherDTO dto) {

		Response<VoucherDTO> response = new Response<>();
		response.setData(voucherServiceImpl.test(dto));
		System.out.println("test");
		return ResponseEntity.status(HttpStatus.CREATED).body(response);
	}

	@GetMapping("/test/{id}")
	@ResponseBody
	public String getAll12(@PathVariable("id") int id) {
		return voucherServiceImpl.sentVoucher(id,"") + "";
	}

	@GetMapping
	public ResponseEntity<Response<List<VoucherDTO>>> getAll() {

		Response<List<VoucherDTO>> response = new Response<>();
		response.setData(this.voucherService.findAll());

		return ResponseEntity.status(HttpStatus.OK).body(response);
	}

	@PreAuthorize("hasAnyRole('ADMIN' or 'RECEPTIONIST')")
	@PostMapping()
	public ResponseEntity<Response<VoucherDTO>> create(@Valid @RequestBody VoucherDTO dto, BindingResult result)
			throws NotParsableContentException {

		Response<VoucherDTO> response = new Response<>();

		if (result.hasErrors()) {
			result.getAllErrors().forEach(error -> response.addErrorMsgToResponse(error.getDefaultMessage()));
			return ResponseEntity.badRequest().body(response);
		}

		if (!ApiUtil.isEndDateGreaterThanStartDate(dto.getStart(), dto.getEnd())) {
			throw new NotParsableContentException("Ngày bắt đầu voucher lớn hơn nhày kết thúc voucher");
		}

		response.setData(this.voucherService.save(dto));

		return ResponseEntity.status(HttpStatus.CREATED).body(response);
	}

	@PreAuthorize("hasAnyRole('ADMIN' or 'RECEPTIONIST')")
	@PutMapping(value = "/{id}")
	public ResponseEntity<Response<VoucherDTO>> update(@Valid @RequestBody VoucherDTO dto, BindingResult result)
			throws NotParsableContentException {

		Response<VoucherDTO> response = new Response<>();

		if (result.hasErrors()) {
			result.getAllErrors().forEach(error -> response.addErrorMsgToResponse(error.getDefaultMessage()));
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
		}

		if (!ApiUtil.isEndDateGreaterThanStartDate(dto.getStart(), dto.getEnd())) {
			throw new NotParsableContentException("Ngày bắt đầu voucher lớn hơn nhày kết thúc voucher");
		}
		response.setData(this.voucherService.update(dto));

		return ResponseEntity.status(HttpStatus.OK).body(response);
	}

	@PreAuthorize("hasAnyRole('ADMIN' or 'RECEPTIONIST')")
	@DeleteMapping(value = "/{id}")
	public void deleteVoucher(@PathVariable("id") String id) throws NotFoundException {
		this.voucherService.hardDelete(id);
	}

	@GetMapping(value = "/byTitle")
	public ResponseEntity<Response<List<VoucherDTO>>> findAllByTitle(@RequestParam(required = false) String title) {
		Response<List<VoucherDTO>> response = new Response<>();

		response.setData(this.voucherService.findByTitle(title));

		return ResponseEntity.status(HttpStatus.OK).body(response);
	}

	@GetMapping(value = "/byId/{id}")
	public ResponseEntity<Response<Optional<VoucherDTO>>> findByID(@PathVariable("id") String id) {
		Response<Optional<VoucherDTO>> response = new Response<>();

		response.setData(this.voucherService.findById(id));

		return ResponseEntity.status(HttpStatus.OK).body(response);
	}

	@GetMapping(value = "/byBetweenDates")
	public ResponseEntity<Response<List<VoucherDTO>>> findAllBetweenDates(
			@RequestParam("startDate") @DateTimeFormat(pattern = "yyyy-MM-dd", iso = DateTimeFormat.ISO.DATE) LocalDate startDate,
			@RequestParam("endDate") @DateTimeFormat(pattern = "yyyy-MM-dd", iso = DateTimeFormat.ISO.DATE) LocalDate endDate

	) throws NotFoundException {

		Response<List<VoucherDTO>> response = new Response<>();

//        System.out.println("start date : " + startDate);
//        System.out.println("end date :" + endDate);
		LocalDateTime startDateTime = ApiUtil.convertLocalDateToLocalDateTime(startDate);
		LocalDateTime endDateTime = ApiUtil.convertLocalDateToLocalDateTime(endDate);

		List<Voucher> vouchers = this.voucherService.findBetweenDates(startDateTime, endDateTime);

		if (vouchers.isEmpty()) {
			throw new NotFoundException(
					"Không có voucher nào đc tạo giữa startDate : " + startDateTime + " và endDate : " + endDateTime);
		}

		List<VoucherDTO> itemDTO = new ArrayList<>();

		vouchers.stream().forEach(t -> itemDTO.add(t.convertEntityToDTO()));

		response.setData(itemDTO);
		return ResponseEntity.status(HttpStatus.OK).body(response);
	}

}
