#ifndef __HOOKING_H
#define __HOOKING_H

#include <stdint.h>

#include "logging.h"

int hook_apis();

// right, gcc's built in frame and return address functions only want constants

#define DUMP_LEVEL(l, ml) { \
	if(l > ml){ \
		break; \
	} \
	if(__builtin_frame_address(l) != NULL){ \
		LOG("0x%016x\n", __builtin_return_address(l)); \
	}else{ \
		break; \
	} \
}

#define DUMP_RET_STACK(ml) { \
	while(1){ \
		DUMP_LEVEL(0, ml); \
		DUMP_LEVEL(1, ml); \
		DUMP_LEVEL(2, ml); \
		DUMP_LEVEL(3, ml); \
		DUMP_LEVEL(4, ml); \
		DUMP_LEVEL(5, ml); \
		DUMP_LEVEL(6, ml); \
		DUMP_LEVEL(7, ml); \
		DUMP_LEVEL(8, ml); \
		DUMP_LEVEL(9, ml); \
		DUMP_LEVEL(10, ml); \
		DUMP_LEVEL(11, ml); \
		DUMP_LEVEL(12, ml); \
		DUMP_LEVEL(13, ml); \
		DUMP_LEVEL(14, ml); \
		DUMP_LEVEL(15, ml); \
		DUMP_LEVEL(16, ml); \
		DUMP_LEVEL(17, ml); \
		DUMP_LEVEL(18, ml); \
		DUMP_LEVEL(19, ml); \
		DUMP_LEVEL(20, ml); \
		DUMP_LEVEL(21, ml); \
		DUMP_LEVEL(22, ml); \
		DUMP_LEVEL(23, ml); \
		DUMP_LEVEL(24, ml); \
		DUMP_LEVEL(25, ml); \
		DUMP_LEVEL(26, ml); \
		DUMP_LEVEL(27, ml); \
		DUMP_LEVEL(28, ml); \
		DUMP_LEVEL(29, ml); \
		DUMP_LEVEL(30, ml); \
		DUMP_LEVEL(31, ml); \
		DUMP_LEVEL(32, ml); \
		DUMP_LEVEL(33, ml); \
		DUMP_LEVEL(34, ml); \
		DUMP_LEVEL(35, ml); \
		DUMP_LEVEL(36, ml); \
		DUMP_LEVEL(37, ml); \
		DUMP_LEVEL(38, ml); \
		DUMP_LEVEL(39, ml); \
		DUMP_LEVEL(40, ml); \
		DUMP_LEVEL(41, ml); \
		DUMP_LEVEL(42, ml); \
		DUMP_LEVEL(43, ml); \
		DUMP_LEVEL(44, ml); \
		DUMP_LEVEL(45, ml); \
		DUMP_LEVEL(46, ml); \
		DUMP_LEVEL(47, ml); \
		DUMP_LEVEL(48, ml); \
		DUMP_LEVEL(49, ml); \
		DUMP_LEVEL(50, ml); \
		DUMP_LEVEL(51, ml); \
		DUMP_LEVEL(52, ml); \
		DUMP_LEVEL(53, ml); \
		DUMP_LEVEL(54, ml); \
		DUMP_LEVEL(55, ml); \
		DUMP_LEVEL(56, ml); \
		DUMP_LEVEL(57, ml); \
		DUMP_LEVEL(58, ml); \
		DUMP_LEVEL(59, ml); \
		DUMP_LEVEL(60, ml); \
		DUMP_LEVEL(61, ml); \
		DUMP_LEVEL(62, ml); \
		DUMP_LEVEL(63, ml); \
		DUMP_LEVEL(64, ml); \
		DUMP_LEVEL(65, ml); \
		DUMP_LEVEL(66, ml); \
		DUMP_LEVEL(67, ml); \
		DUMP_LEVEL(68, ml); \
		DUMP_LEVEL(69, ml); \
		DUMP_LEVEL(70, ml); \
		DUMP_LEVEL(71, ml); \
		DUMP_LEVEL(72, ml); \
		DUMP_LEVEL(73, ml); \
		DUMP_LEVEL(74, ml); \
		DUMP_LEVEL(75, ml); \
		DUMP_LEVEL(76, ml); \
		DUMP_LEVEL(77, ml); \
		DUMP_LEVEL(78, ml); \
		DUMP_LEVEL(79, ml); \
		DUMP_LEVEL(80, ml); \
		DUMP_LEVEL(81, ml); \
		DUMP_LEVEL(82, ml); \
		DUMP_LEVEL(83, ml); \
		DUMP_LEVEL(84, ml); \
		DUMP_LEVEL(85, ml); \
		DUMP_LEVEL(86, ml); \
		DUMP_LEVEL(87, ml); \
		DUMP_LEVEL(88, ml); \
		DUMP_LEVEL(89, ml); \
		DUMP_LEVEL(90, ml); \
		DUMP_LEVEL(91, ml); \
		DUMP_LEVEL(92, ml); \
		DUMP_LEVEL(93, ml); \
		DUMP_LEVEL(94, ml); \
		DUMP_LEVEL(95, ml); \
		DUMP_LEVEL(96, ml); \
		DUMP_LEVEL(97, ml); \
		DUMP_LEVEL(98, ml); \
		DUMP_LEVEL(99, ml); \
		DUMP_LEVEL(100, ml); \
		DUMP_LEVEL(101, ml); \
		DUMP_LEVEL(102, ml); \
		DUMP_LEVEL(103, ml); \
		DUMP_LEVEL(104, ml); \
		DUMP_LEVEL(105, ml); \
		DUMP_LEVEL(106, ml); \
		DUMP_LEVEL(107, ml); \
		DUMP_LEVEL(108, ml); \
		DUMP_LEVEL(109, ml); \
		DUMP_LEVEL(110, ml); \
		DUMP_LEVEL(111, ml); \
		DUMP_LEVEL(112, ml); \
		DUMP_LEVEL(113, ml); \
		DUMP_LEVEL(114, ml); \
		DUMP_LEVEL(115, ml); \
		DUMP_LEVEL(116, ml); \
		DUMP_LEVEL(117, ml); \
		DUMP_LEVEL(118, ml); \
		DUMP_LEVEL(119, ml); \
		DUMP_LEVEL(120, ml); \
		DUMP_LEVEL(121, ml); \
		DUMP_LEVEL(122, ml); \
		DUMP_LEVEL(123, ml); \
		DUMP_LEVEL(124, ml); \
		DUMP_LEVEL(125, ml); \
		DUMP_LEVEL(126, ml); \
		DUMP_LEVEL(127, ml); \
		DUMP_LEVEL(128, ml); \
		DUMP_LEVEL(129, ml); \
		DUMP_LEVEL(130, ml); \
		DUMP_LEVEL(131, ml); \
		DUMP_LEVEL(132, ml); \
		DUMP_LEVEL(133, ml); \
		DUMP_LEVEL(134, ml); \
		DUMP_LEVEL(135, ml); \
		DUMP_LEVEL(136, ml); \
		DUMP_LEVEL(137, ml); \
		DUMP_LEVEL(138, ml); \
		DUMP_LEVEL(139, ml); \
		DUMP_LEVEL(140, ml); \
		DUMP_LEVEL(141, ml); \
		DUMP_LEVEL(142, ml); \
		DUMP_LEVEL(143, ml); \
		DUMP_LEVEL(144, ml); \
		DUMP_LEVEL(145, ml); \
		DUMP_LEVEL(146, ml); \
		DUMP_LEVEL(147, ml); \
		DUMP_LEVEL(148, ml); \
		DUMP_LEVEL(149, ml); \
		DUMP_LEVEL(150, ml); \
		DUMP_LEVEL(151, ml); \
		DUMP_LEVEL(152, ml); \
		DUMP_LEVEL(153, ml); \
		DUMP_LEVEL(154, ml); \
		DUMP_LEVEL(155, ml); \
		DUMP_LEVEL(156, ml); \
		DUMP_LEVEL(157, ml); \
		DUMP_LEVEL(158, ml); \
		DUMP_LEVEL(159, ml); \
		DUMP_LEVEL(160, ml); \
		DUMP_LEVEL(161, ml); \
		DUMP_LEVEL(162, ml); \
		DUMP_LEVEL(163, ml); \
		DUMP_LEVEL(164, ml); \
		DUMP_LEVEL(165, ml); \
		DUMP_LEVEL(166, ml); \
		DUMP_LEVEL(167, ml); \
		DUMP_LEVEL(168, ml); \
		DUMP_LEVEL(169, ml); \
		DUMP_LEVEL(170, ml); \
		DUMP_LEVEL(171, ml); \
		DUMP_LEVEL(172, ml); \
		DUMP_LEVEL(173, ml); \
		DUMP_LEVEL(174, ml); \
		DUMP_LEVEL(175, ml); \
		DUMP_LEVEL(176, ml); \
		DUMP_LEVEL(177, ml); \
		DUMP_LEVEL(178, ml); \
		DUMP_LEVEL(179, ml); \
		DUMP_LEVEL(180, ml); \
		DUMP_LEVEL(181, ml); \
		DUMP_LEVEL(182, ml); \
		DUMP_LEVEL(183, ml); \
		DUMP_LEVEL(184, ml); \
		DUMP_LEVEL(185, ml); \
		DUMP_LEVEL(186, ml); \
		DUMP_LEVEL(187, ml); \
		DUMP_LEVEL(188, ml); \
		DUMP_LEVEL(189, ml); \
		DUMP_LEVEL(190, ml); \
		DUMP_LEVEL(191, ml); \
		DUMP_LEVEL(192, ml); \
		DUMP_LEVEL(193, ml); \
		DUMP_LEVEL(194, ml); \
		DUMP_LEVEL(195, ml); \
		DUMP_LEVEL(196, ml); \
		DUMP_LEVEL(197, ml); \
		DUMP_LEVEL(198, ml); \
		DUMP_LEVEL(199, ml); \
		DUMP_LEVEL(200, ml); \
		DUMP_LEVEL(201, ml); \
		DUMP_LEVEL(202, ml); \
		DUMP_LEVEL(203, ml); \
		DUMP_LEVEL(204, ml); \
		DUMP_LEVEL(205, ml); \
		DUMP_LEVEL(206, ml); \
		DUMP_LEVEL(207, ml); \
		DUMP_LEVEL(208, ml); \
		DUMP_LEVEL(209, ml); \
		DUMP_LEVEL(210, ml); \
		DUMP_LEVEL(211, ml); \
		DUMP_LEVEL(212, ml); \
		DUMP_LEVEL(213, ml); \
		DUMP_LEVEL(214, ml); \
		DUMP_LEVEL(215, ml); \
		DUMP_LEVEL(216, ml); \
		DUMP_LEVEL(217, ml); \
		DUMP_LEVEL(218, ml); \
		DUMP_LEVEL(219, ml); \
		DUMP_LEVEL(220, ml); \
		DUMP_LEVEL(221, ml); \
		DUMP_LEVEL(222, ml); \
		DUMP_LEVEL(223, ml); \
		DUMP_LEVEL(224, ml); \
		DUMP_LEVEL(225, ml); \
		DUMP_LEVEL(226, ml); \
		DUMP_LEVEL(227, ml); \
		DUMP_LEVEL(228, ml); \
		DUMP_LEVEL(229, ml); \
		DUMP_LEVEL(230, ml); \
		DUMP_LEVEL(231, ml); \
		DUMP_LEVEL(232, ml); \
		DUMP_LEVEL(233, ml); \
		DUMP_LEVEL(234, ml); \
		DUMP_LEVEL(235, ml); \
		DUMP_LEVEL(236, ml); \
		DUMP_LEVEL(237, ml); \
		DUMP_LEVEL(238, ml); \
		DUMP_LEVEL(239, ml); \
		DUMP_LEVEL(240, ml); \
		DUMP_LEVEL(241, ml); \
		DUMP_LEVEL(242, ml); \
		DUMP_LEVEL(243, ml); \
		DUMP_LEVEL(244, ml); \
		DUMP_LEVEL(245, ml); \
		DUMP_LEVEL(246, ml); \
		DUMP_LEVEL(247, ml); \
		DUMP_LEVEL(248, ml); \
		DUMP_LEVEL(249, ml); \
		DUMP_LEVEL(250, ml); \
		DUMP_LEVEL(251, ml); \
		DUMP_LEVEL(252, ml); \
		DUMP_LEVEL(253, ml); \
		DUMP_LEVEL(254, ml); \
		DUMP_LEVEL(255, ml); \
		break; \
	} \
}

#endif
